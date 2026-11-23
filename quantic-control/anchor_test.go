package control

import (
    "bytes"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/json"
    "os"
    "testing"
    "time"
)

func makeSignedAnchor(t *testing.T, d *DurableGuard, authorityID string, priv ed25519.PrivateKey) SignedAnchor {
    t.Helper()
    payload, err := d.AnchorProposal(authorityID)
    if err != nil { t.Fatal(err) }
    msg, err := AnchorSigningBytes(payload)
    if err != nil { t.Fatal(err) }
    return SignedAnchor{Payload:payload, Signature:ed25519.Sign(priv,msg)}
}

func TestPinnedAnchorPassesAcrossRestartAndRejectsRollback(t *testing.T) {
    path, keys, operatorPriv := setupState(t)
    authorityPub, authorityPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    now := time.Now()
    d, err := InitDurableGuard(path,"machine-1",keys)
    if err != nil { t.Fatal(err) }
    if err := d.Authorize(request(t,"first-unique-nonce-01",operatorPriv,now),now); err != nil { t.Fatal(err) }
    rolledBack, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    if err := d.Authorize(request(t,"second-unique-nonce02",operatorPriv,now),now); err != nil { t.Fatal(err) }
    anchor := makeSignedAnchor(t,d,"offline-vault",authorityPriv)
    if err := d.Close(); err != nil { t.Fatal(err) }
    opened, err := OpenPinnedDurableGuard(path,"machine-1",keys,anchor,"offline-vault",authorityPub)
    if err != nil { t.Fatal(err) }
    if err := opened.Close(); err != nil { t.Fatal(err) }

    // Restore a fully valid earlier journal snapshot. It passes hash-chain
    // verification without the independent pinned anchor, but not with it.
    if err := os.WriteFile(path,rolledBack,0600); err != nil { t.Fatal(err) }
    unpinned, err := OpenDurableGuard(path,"machine-1",keys)
    if err != nil { t.Fatalf("expected earlier self-consistent journal to load: %v",err) }
    _ = unpinned.Close()
    if _, err := OpenPinnedDurableGuard(path,"machine-1",keys,anchor,"offline-vault",authorityPub); err == nil {
        t.Fatal("signed anchor did not detect rollback")
    }
}

func TestPinnedAnchorRejectsForgedAndStaleSignatures(t *testing.T) {
    path, keys, operatorPriv := setupState(t)
    authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    d, err := InitDurableGuard(path,"machine-1",keys)
    if err != nil { t.Fatal(err) }
    anchor := makeSignedAnchor(t,d,"offline-vault",authPriv)
    if err := d.VerifyPinnedAnchor(anchor,"offline-vault",authPub); err != nil { t.Fatal(err) }
    wrong := anchor
    wrong.Payload.MachineID="machine-2"
    if err := d.VerifyPinnedAnchor(wrong,"offline-vault",authPub); err == nil { t.Fatal("modified machine accepted") }
    wrong=anchor
    wrong.Signature=append([]byte{},anchor.Signature...)
    wrong.Signature[0]^=0x01
    if err := d.VerifyPinnedAnchor(wrong,"offline-vault",authPub); err == nil { t.Fatal("forged signature accepted") }
    otherPub, _, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    if err := d.VerifyPinnedAnchor(anchor,"offline-vault",otherPub); err == nil { t.Fatal("untrusted signing authority accepted") }
    if err := d.VerifyPinnedAnchor(anchor,"not-the-authority",authPub); err == nil { t.Fatal("wrong authority ID accepted") }
    if err := d.VerifyPinnedAnchor(anchor,"offline-vault",keys["admin"]); err == nil { t.Fatal("operator key reused as signing authority") }
    now:=time.Now()
    if err := d.Authorize(request(t,"third-unique-nonce-03",operatorPriv,now),now); err != nil { t.Fatal(err) }
    if err := d.VerifyPinnedAnchor(anchor,"offline-vault",authPub); err == nil { t.Fatal("stale signed checkpoint accepted") }
    _ = d.Close()
}

func TestPinnedAnchorRejectsRewrittenValidHashChain(t *testing.T) {
    path, keys, operatorPriv := setupState(t)
    authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    now:=time.Now()
    d,err:=InitDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    if err:=d.Authorize(request(t,"original-nonce-0001",operatorPriv,now),now);err!=nil {t.Fatal(err)}
    anchor:=makeSignedAnchor(t,d,"offline-vault",authPriv)
    if err:=d.Close();err!=nil {t.Fatal(err)}
    raw,err:=os.ReadFile(path);if err!=nil {t.Fatal(err)}
    lines:=bytes.Split(bytes.TrimSuffix(raw,[]byte{'\n'}),[]byte{'\n'})
    if len(lines)!=2 {t.Fatalf("unexpected entries: %d",len(lines))}
    var tampered journalRecord
    if err:=json.Unmarshal(lines[1],&tampered);err!=nil {t.Fatal(err)}
    tampered.Nonce="different-nonce-0002"
    digest,err:=hashRecord(tampered);if err!=nil {t.Fatal(err)}
    tampered.Digest=digest
    changed,err:=json.Marshal(tampered);if err!=nil {t.Fatal(err)}
    newFile:=append(append(append([]byte{},lines[0]...), '\n'),changed...)
    newFile=append(newFile,'\n')
    if err:=os.WriteFile(path,newFile,0600);err!=nil {t.Fatal(err)}
    validButForged,err:=OpenDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatalf("expected syntactically correct rewritten chain: %v",err)}
    _=validButForged.Close()
    if _,err:=OpenPinnedDurableGuard(path,"machine-1",keys,anchor,"offline-vault",authPub);err==nil {
        t.Fatal("signed independent anchor did not reject rewritten journal")
    }
}

func TestAnchorPayloadValidation(t *testing.T) {
    if _,err:=AnchorSigningBytes(AnchorPayload{Version:1,MachineID:"x",Sequence:1,AuthorityID:"a",JournalHead:"oops"});err==nil {t.Fatal("invalid hash accepted")}
    if _,err:=AnchorSigningBytes(AnchorPayload{});err==nil {t.Fatal("zero payload accepted")}
}
