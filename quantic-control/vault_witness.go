package control

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "time"
)

const vaultWitnessCapacity = 16384 // Matches Quantic native Vault anchor_server.py CAP.

// VaultWitnessConfig is supplied by an independently trusted local authority.
// The TLS certificate and key are never written to this package's journal.
type VaultWitnessConfig struct {
    Endpoint string
    ServerCAPEM []byte
    ServerCertSHA256 string
    ClientCertificate tls.Certificate
}

// VaultWitness is a strict client for the pre-existing native Identity Vault
// /check and /advance checkpoint endpoints. It never creates, resets or
// revokes a witness identity and never exposes shell or management endpoints.
type VaultWitness struct {
    endpoint string
    client *http.Client
}

func NewVaultWitness(c VaultWitnessConfig) (*VaultWitness, error) {
    u, err := url.Parse(c.Endpoint)
    if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" ||
        u.RawQuery != "" || u.Fragment != "" || !validSHA256(c.ServerCertSHA256) {
        return nil, errors.New("vault witness endpoint or server pin is invalid")
    }
    roots := x509.NewCertPool()
    if !roots.AppendCertsFromPEM(c.ServerCAPEM) || len(c.ClientCertificate.Certificate) == 0 || c.ClientCertificate.PrivateKey == nil {
        return nil, errors.New("vault witness requires explicit CA and mutual TLS certificate")
    }
    config := &tls.Config{
        MinVersion: tls.VersionTLS13,
        RootCAs: roots,
        Certificates: []tls.Certificate{c.ClientCertificate},
        VerifyConnection: func(state tls.ConnectionState) error {
            if len(state.PeerCertificates) == 0 { return errors.New("vault witness server certificate missing") }
            digest := sha256.Sum256(state.PeerCertificates[0].Raw)
            if hex.EncodeToString(digest[:]) != c.ServerCertSHA256 { return errors.New("vault witness server certificate pin mismatch") }
            return nil
        },
    }
    transport := &http.Transport{TLSClientConfig:config, DisableCompression:true, Proxy:nil, ResponseHeaderTimeout:3*time.Second}
    client := &http.Client{Transport:transport, Timeout:5*time.Second, CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("vault witness redirect forbidden")}}
    return &VaultWitness{endpoint:c.Endpoint, client:client},nil
}

// VaultWitnessCursor corresponds exactly to the existing independent Vault
// SQLite checkpoint record (id, count, tail). It must be independently pinned
// by the caller, never silently taken from an untrusted local file.
type VaultWitnessCursor struct {
    ID string
    Count int
    Tail string
}

func InitialVaultWitnessCursor(id string) (VaultWitnessCursor,error) {
    if !validSHA256(id) { return VaultWitnessCursor{},errors.New("invalid independently provisioned witness identifier") }
    return VaultWitnessCursor{ID:id, Count:0, Tail:id}, nil
}

func validCursor(c VaultWitnessCursor) bool {
    return validSHA256(c.ID) && validSHA256(c.Tail) && c.Count >= 0 && c.Count <= vaultWitnessCapacity
}

func (w *VaultWitness) call(ctx context.Context, op string, cursor VaultWitnessCursor, record string) error {
    if w == nil || w.client == nil { return errors.New("vault witness unavailable") }
    if !validCursor(cursor) { return errors.New("invalid vault witness cursor") }
    if op != "check" && op != "advance" { return errors.New("unsupported witness operation") }
    if op == "advance" && (cursor.Count >= vaultWitnessCapacity || !validSHA256(record)) {
        return errors.New("invalid witness advancement")
    }
    body := struct {
        ID string `json:"id"`
        Count int `json:"count"`
        Tail string `json:"tail"`
        Record string `json:"record,omitempty"`
    }{ID:cursor.ID,Count:cursor.Count,Tail:cursor.Tail}
    if op == "advance" {body.Record=record}
    encoded,err:=json.Marshal(body)
    if err!=nil { return err }
    req,err:=http.NewRequestWithContext(ctx,http.MethodPost,w.endpoint+"/"+op,bytes.NewReader(encoded))
    if err!=nil{return err}
    req.Header.Set("Content-Type","application/json")
    resp,err:=w.client.Do(req)
    if err!=nil{return fmt.Errorf("independent vault witness unavailable or refused: %w",err)}
    defer resp.Body.Close()
    reply,err:=io.ReadAll(io.LimitReader(resp.Body,129))
    if err!=nil || resp.StatusCode!=http.StatusOK || !bytes.Equal(reply,[]byte("OK\n")) {
        return errors.New("independent vault witness refused checkpoint")
    }
    return nil
}

// Check rejects a local checkpoint absent from the remote, append-only
// independent service. It makes no remote changes.
func (w *VaultWitness) Check(ctx context.Context, cursor VaultWitnessCursor) error {
    return w.call(ctx,"check",cursor,"")
}

// Advance atomically advances the independent service from precisely the old
// cursor. A failed/ambiguous response is NOT retried automatically. Callers
// must explicitly reconcile ambiguous commits through trusted recovery.
// VaultWitnessTransition binds the latest independently checked witness state
// to the exact signed anchor recorded in that transition.
type VaultWitnessTransition struct {
    Before VaultWitnessCursor
    After VaultWitnessCursor
    RecordDigest string
}

func nextVaultWitnessCursor(before VaultWitnessCursor, record string) (VaultWitnessCursor, error) {
    if !validCursor(before) || before.Count >= vaultWitnessCapacity || !validSHA256(record) {
        return VaultWitnessCursor{},errors.New("invalid witness transition")
    }
    oldTail,_:=hex.DecodeString(before.Tail)
    recordBytes,_:=hex.DecodeString(record)
    sum:=sha256.Sum256(append(oldTail,recordBytes...))
    return VaultWitnessCursor{ID:before.ID,Count:before.Count+1,Tail:hex.EncodeToString(sum[:])},nil
}

// Advance atomically advances the independent service from precisely the old
// cursor. A failed/ambiguous response is NOT retried automatically.
func (w *VaultWitness) Advance(ctx context.Context, cursor VaultWitnessCursor, record string) (VaultWitnessTransition,error) {
    next,err:=nextVaultWitnessCursor(cursor,record)
    if err!=nil{return VaultWitnessTransition{},err}
    if err:=w.call(ctx,"advance",cursor,record);err!=nil{return VaultWitnessTransition{},err}
    return VaultWitnessTransition{Before:cursor,After:next,RecordDigest:record},nil
}

// WitnessRecordDigest binds the signed, independently sourced anchor to a
// Vault witness record, without giving the witness private keys or the journal.
func WitnessRecordDigest(anchor SignedAnchor) (string,error) {
    if _,err:=AnchorSigningBytes(anchor.Payload);err!=nil{return "",err}
    if len(anchor.Signature)!=ed25519.SignatureSize {return "",errors.New("invalid anchor signature length")}
    raw,err:=json.Marshal(anchor)
    if err!=nil{return "",err}
    sum:=sha256.Sum256(append([]byte("QUANTIC-CONTROL/vault-witness-record/v1\n"),raw...))
    return hex.EncodeToString(sum[:]),nil
}

// validateWitnessTransition prevents a client from presenting a current witness
// cursor alongside a different, stale signed anchor. It verifies the complete
// hash link (previous cursor || digest of this exact signed anchor) -> next.
func validateWitnessTransition(anchor SignedAnchor, transition VaultWitnessTransition) error {
    digest,err:=WitnessRecordDigest(anchor)
    if err!=nil{return err}
    if transition.RecordDigest!=digest{return errors.New("witness is not bound to signed anchor")}
    expected,err:=nextVaultWitnessCursor(transition.Before,digest)
    if err!=nil{return err}
    if expected!=transition.After{return errors.New("witness cursor does not follow signed anchor")}
    return nil
}

// CheckPinnedVaultWitness verifies the signed local journal AND the exact
// hash transition that commits THIS anchor to the current independent witness.
// It is still a snapshot check, not an atomic remote-operation permission.
func (d *DurableGuard) CheckPinnedVaultWitness(ctx context.Context, witness *VaultWitness,
    anchor SignedAnchor, authorityID string, authorityPub ed25519.PublicKey, transition VaultWitnessTransition) error {
    if err:=d.VerifyPinnedAnchor(anchor,authorityID,authorityPub);err!=nil{return err}
    if err:=validateWitnessTransition(anchor,transition);err!=nil{return err}
    return witness.Check(ctx,transition.After)
}

// AdvancePinnedVaultWitness requires a verified current snapshot and returns
// the exact signed-anchor-to-witness transition. Hold the trust roots outside
// the machine's rollback domain; do not retry an ambiguous /advance response.
func (d *DurableGuard) AdvancePinnedVaultWitness(ctx context.Context,witness *VaultWitness,
    anchor SignedAnchor,authorityID string,authorityPub ed25519.PublicKey,cursor VaultWitnessCursor)(VaultWitnessTransition,error){
    if err:=d.VerifyPinnedAnchor(anchor,authorityID,authorityPub);err!=nil{return VaultWitnessTransition{},err}
    record,err:=WitnessRecordDigest(anchor)
    if err!=nil{return VaultWitnessTransition{},err}
    return witness.Advance(ctx,cursor,record)
}
