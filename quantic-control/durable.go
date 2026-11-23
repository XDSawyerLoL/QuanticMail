package control

import (
    "bytes"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "runtime"
    "sync"
    "time"
)

const (
    durableVersion = 1
    maxJournalBytes = 64 << 20
    maxJournalRecords = 100000
)

var errStateUnavailable = errors.New("durable authorization unavailable (fail closed)")

type journalRecord struct {
    Version int `json:"version"`
    Sequence uint64 `json:"sequence"`
    Previous string `json:"previous"`
    Kind string `json:"kind"`
    MachineID string `json:"machine_id"`
    Keys map[string][]byte `json:"keys,omitempty"`
    KeyID string `json:"key_id,omitempty"`
    Nonce string `json:"nonce,omitempty"`
    ExpiresAt int64 `json:"expires_at,omitempty"`
    Digest string `json:"digest"`
}

// DurableGuard is a single-process, local-only authorization guard. It never
// launches commands and never opens a network listener. Authorized nonces and
// revocations are recorded and fsynced BEFORE the call reports success.
// The journal hash chain detects accidental corruption, NOT hostile rollback
// or rewriting by someone who has gained local write privileges.
type DurableGuard struct {
    mu sync.Mutex
    file *os.File
    guard *Guard
    machineID string
    used map[string]bool
    revoked map[string]bool
    sequence uint64
    head string
    bytesWritten int64
    poisoned bool
}

// InitDurableGuard is an explicit, one-time local enrollment ceremony. It
// refuses to replace an existing file, including an existing corrupted one.
func InitDurableGuard(path, machineID string, keys map[string]ed25519.PublicKey) (*DurableGuard, error) {
    if len(keys) == 0 { return nil, errors.New("at least one operator key is required") }
    g, err := NewGuard(machineID, keys)
    if err != nil { return nil, err }
    if err := checkStateParent(path); err != nil { return nil, err }
    f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0600)
    if err != nil { return nil, err }
    if err := lockStateFile(f); err != nil { f.Close(); return nil, fmt.Errorf("cannot exclusively lock state: %w", err) }
    d := &DurableGuard{file:f, guard:g, machineID:machineID, used:map[string]bool{}, revoked:map[string]bool{}}
    enrolled := make(map[string][]byte, len(keys))
    for id, key := range keys { enrolled[id] = append([]byte(nil), key...) }
    if err := d.append(journalRecord{Kind:"enroll", MachineID:machineID, Keys:enrolled}); err != nil {
        _ = d.Close()
        return nil, fmt.Errorf("initial state write failed; inspect and recover manually: %w", err)
    }
    // Sync the directory entry on platforms that support directory fsync.
    if runtime.GOOS != "windows" {
        parent, err := os.Open(filepath.Dir(path))
        if err != nil { _ = d.Close(); return nil, err }
        err = parent.Sync()
        _ = parent.Close()
        if err != nil { _ = d.Close(); return nil, err }
    }
    return d, nil
}

// OpenDurableGuard requires the original, independently pinned public keys.
// Missing, truncated, corrupted or conflicting state is rejected: there is
// deliberately no automatic repair, re-enrollment or journal truncation.
func OpenDurableGuard(path, machineID string, keys map[string]ed25519.PublicKey) (*DurableGuard, error) {
    if len(keys) == 0 { return nil, errors.New("trusted public keys required") }
    if err := checkStateParent(path); err != nil { return nil, err }
    before, err := os.Lstat(path)
    if err != nil { return nil, fmt.Errorf("state missing or inaccessible: %w", err) }
    if !before.Mode().IsRegular() { return nil, errors.New("state must be a regular non-symlink file") }
    if runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 { return nil, errors.New("state permissions too broad") }
    if before.Size() == 0 || before.Size() > maxJournalBytes { return nil, errors.New("state size invalid") }
    f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
    if err != nil { return nil, err }
    after, err := f.Stat()
    if err != nil || !os.SameFile(before, after) { _ = f.Close(); return nil, errors.New("state was swapped during open") }
    if err := lockStateFile(f); err != nil { _ = f.Close(); return nil, fmt.Errorf("state already in use: %w", err) }
    d := &DurableGuard{file:f, machineID:machineID, used:map[string]bool{}, revoked:map[string]bool{}}
    if err := d.load(keys); err != nil { _ = d.Close(); return nil, err }
    return d, nil
}

func checkStateParent(path string) error {
    if path == "" { return errors.New("state path is required") }
    dir := filepath.Dir(path)
    st, err := os.Stat(dir)
    if err != nil { return err }
    if !st.IsDir() { return errors.New("state parent is not a directory") }
    if runtime.GOOS != "windows" && st.Mode().Perm()&0022 != 0 {
        return errors.New("state parent is writable by group or others")
    }
    return nil
}

func hashRecord(r journalRecord) (string, error) {
    r.Digest = ""
    b, err := json.Marshal(r)
    if err != nil { return "", err }
    sum := sha256.Sum256(append([]byte("QUANTIC-CONTROL/journal/v1\n"), b...))
    return hex.EncodeToString(sum[:]), nil
}

func (d *DurableGuard) append(r journalRecord) error {
    if d.poisoned || d.file == nil { return errStateUnavailable }
    if d.sequence >= maxJournalRecords || d.bytesWritten >= maxJournalBytes {
        d.poisoned = true
        return errors.New("journal capacity reached; authorization stopped")
    }
    r.Version = durableVersion
    r.Sequence = d.sequence + 1
    r.Previous = d.head
    hash, err := hashRecord(r)
    if err != nil { d.poisoned=true; return err }
    r.Digest=hash
    b, err:=json.Marshal(r)
    if err!=nil { d.poisoned=true; return err }
    b=append(b,'\n')
    if d.bytesWritten+int64(len(b)) > maxJournalBytes { d.poisoned=true; return errors.New("journal full") }
    n, err:=d.file.Write(b)
    if err!=nil || n!=len(b) {
        d.poisoned=true
        if err==nil {err=io.ErrShortWrite}
        return fmt.Errorf("journal write failed: %w",err)
    }
    if err:=d.file.Sync();err!=nil {d.poisoned=true;return fmt.Errorf("journal sync failed: %w",err)}
    d.sequence=r.Sequence
    d.head=hash
    d.bytesWritten+=int64(len(b))
    return nil
}

func (d *DurableGuard) load(expected map[string]ed25519.PublicKey) error {
    if _,err:=d.file.Seek(0,io.SeekStart);err!=nil {return err}
    data,err:=io.ReadAll(io.LimitReader(d.file,maxJournalBytes+1))
    if err!=nil {return err}
    if len(data)==0 || len(data)>maxJournalBytes || data[len(data)-1]!='\n' {
        return errors.New("journal incomplete or oversized; fail closed")
    }
    parts:=bytes.Split(data[:len(data)-1],[]byte{'\n'})
    if len(parts)>maxJournalRecords {return errors.New("too many journal records")}
    var stored map[string][]byte
    for index,line:=range parts {
        dec:=json.NewDecoder(bytes.NewReader(line))
        dec.DisallowUnknownFields()
        var r journalRecord
        if err:=dec.Decode(&r);err!=nil {return fmt.Errorf("journal entry %d malformed: %w",index+1,err)}
        var extra any
        if err:=dec.Decode(&extra);err!=io.EOF {return fmt.Errorf("journal entry %d has trailing data",index+1)}
        if r.Version!=durableVersion || r.Sequence!=uint64(index+1) || r.Previous!=d.head || r.MachineID!=d.machineID {
            return fmt.Errorf("journal entry %d has inconsistent identity or sequence",index+1)
        }
        hash,err:=hashRecord(r)
        if err!=nil || r.Digest!=hash {return fmt.Errorf("journal entry %d has invalid digest",index+1)}
        if index==0 {
            if r.Kind!="enroll" || r.KeyID!="" || r.Nonce!="" || len(r.Keys)==0 {
                return errors.New("invalid enrollment record")
            }
            stored=r.Keys
            if len(stored)!=len(expected) {return errors.New("trusted key enrollment mismatch")}
            for id,key:=range expected {
                if id=="" || len(key)!=ed25519.PublicKeySize || !bytes.Equal(key,stored[id]) {
                    return errors.New("trusted key enrollment mismatch")
                }
            }
        } else {
            if len(r.Keys)!=0 || r.KeyID=="" {return fmt.Errorf("invalid journal event %d",index+1)}
            if _,known:=stored[r.KeyID];!known {return fmt.Errorf("unknown key in journal event %d",index+1)}
            switch r.Kind {
            case "used":
                if len(r.Nonce)<16 || len(r.Nonce)>128 || r.ExpiresAt<=0 {return errors.New("invalid nonce journal event")}
                nonceKey:=r.KeyID+":"+r.Nonce
                if d.used[nonceKey] {return errors.New("duplicate nonce in journal")}
                d.used[nonceKey]=true
            case "revoke":
                if r.Nonce!="" || r.ExpiresAt!=0 || d.revoked[r.KeyID] {return errors.New("invalid revocation event")}
                d.revoked[r.KeyID]=true
            default: return errors.New("unsupported journal event")
            }
        }
        d.head=hash
        d.sequence=r.Sequence
    }
    g,err:=NewGuard(d.machineID,expected)
    if err!=nil {return err}
    for key:=range d.revoked {g.Revoke(key)}
    d.guard=g
    d.bytesWritten=int64(len(data))
    return nil
}

// Authorize records the signed request BEFORE returning success. It remains
// rejected after restart, including if the system clock is moved backwards.
func(d *DurableGuard) Authorize(req SignedRequest,now time.Time) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    if d.poisoned || d.file==nil {return errStateUnavailable}
    k:=req.Claims.KeyID+":"+req.Claims.Nonce
    if d.used[k] {return errors.New("replay rejected (durable nonce)")}
    if err:=d.guard.Authorize(req,now);err!=nil {return err}
    if err:=d.append(journalRecord{Kind:"used",MachineID:d.machineID,KeyID:req.Claims.KeyID,Nonce:req.Claims.Nonce,ExpiresAt:req.Claims.ExpiresAt});err!=nil {return err}
    d.used[k]=true
    return nil
}

// Revoke persists the rejection before changing in-memory policy.
func(d *DurableGuard) Revoke(keyID string) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    if d.poisoned || d.file==nil {return errStateUnavailable}
    if _,exists:=d.guard.keys[keyID];!exists {return errors.New("key not enrolled")}
    if d.revoked[keyID] {return nil}
    if err:=d.append(journalRecord{Kind:"revoke",MachineID:d.machineID,KeyID:keyID});err!=nil {return err}
    d.revoked[keyID]=true
    d.guard.Revoke(keyID)
    return nil
}

func(d *DurableGuard) Close() error {
    d.mu.Lock()
    defer d.mu.Unlock()
    if d.file==nil {return nil}
    d.poisoned=true
    err:=unlockStateFile(d.file)
    closeErr:=d.file.Close()
    d.file=nil
    if err!=nil {return err}
    return closeErr
}

// JournalHealth returns only public counters; the journal can contain
// identifiable machine/key metadata, so it must not be uploaded by default.
func(d *DurableGuard) JournalHealth()(uint64,bool) {
    d.mu.Lock();defer d.mu.Unlock()
    return d.sequence, !d.poisoned && d.file!=nil
}
