package control

import (
    "bytes"
    "crypto/ed25519"
    "crypto/rand"
    "errors"
    "os"
    "path/filepath"
    "testing"
    "time"
)

func signer(t *testing.T, claims Claims, priv ed25519.PrivateKey) SignedRequest {
    t.Helper()
    b,err:=SigningBytes(claims);if err!=nil {t.Fatal(err)}
    return SignedRequest{Claims:claims,Signature:ed25519.Sign(priv,b)}
}
func setupState(t *testing.T)(string,map[string]ed25519.PublicKey,ed25519.PrivateKey) {
    t.Helper()
    pub,priv,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil {t.Fatal(err)}
    dir:=filepath.Join(t.TempDir(),"private")
    if err:=os.Mkdir(dir,0700);err!=nil {t.Fatal(err)}
    return filepath.Join(dir,"authorization.journal"),map[string]ed25519.PublicKey{"admin":pub},priv
}
func request(t *testing.T, nonce string, private ed25519.PrivateKey, now time.Time) SignedRequest {
    t.Helper()
    return signer(t,Claims{Version:1,MachineID:"machine-1",Action:"status.read",KeyID:"admin",Nonce:nonce,IssuedAt:now.Unix(),ExpiresAt:now.Add(time.Minute).Unix()},private)
}
func TestPersistentReplayAfterRestartAndClockRollback(t *testing.T) {
    path,keys,priv:=setupState(t)
    now:=time.Now()
    g,err:=InitDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    r:=request(t,"abcdefghijklmnop",priv,now)
    if err:=g.Authorize(r,now);err!=nil {t.Fatal(err)}
    if err:=g.Close();err!=nil {t.Fatal(err)}
    g,err=OpenDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    defer g.Close()
    if err:=g.Authorize(r,now);err==nil {t.Fatal("replay allowed across restart")}
    if err:=g.Authorize(r,now.Add(-30*time.Second));err==nil {t.Fatal("replay allowed after clock rollback")}
    if err:=g.Authorize(request(t,"different-nonce-1234",priv,now),now);err!=nil {t.Fatal(err)}
}
func TestPersistentRevocationAndExclusiveOpen(t *testing.T) {
    path,keys,priv:=setupState(t)
    g,err:=InitDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    if _,err:=OpenDurableGuard(path,"machine-1",keys);err==nil {t.Fatal("concurrent open succeeded")}
    if err:=g.Revoke("admin");err!=nil {t.Fatal(err)}
    if err:=g.Close();err!=nil {t.Fatal(err)}
    reopened,err:=OpenDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    defer reopened.Close()
    now:=time.Now()
    if err:=reopened.Authorize(request(t,"abcdefghijklmnop",priv,now),now);err==nil {t.Fatal("revoked key used after restart")}
    if err:=reopened.Revoke("missing");err==nil {t.Fatal("unknown revocation allowed")}
}
func TestJournalCorruptionFailsClosed(t *testing.T) {
    path,keys,_:=setupState(t)
    g,err:=InitDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    if err:=g.Close();err!=nil {t.Fatal(err)}
    b,err:=os.ReadFile(path)
    if err!=nil {t.Fatal(err)}
    corrupted:=bytes.Replace(b,[]byte("machine-1"),[]byte("machine-2"),1)
    if err:=os.WriteFile(path,corrupted,0600);err!=nil {t.Fatal(err)}
    if _,err:=OpenDurableGuard(path,"machine-1",keys);err==nil {t.Fatal("tampered journal accepted")}
    if err:=os.WriteFile(path,b[:len(b)-1],0600);err!=nil {t.Fatal(err)}
    if _,err:=OpenDurableGuard(path,"machine-1",keys);err==nil {t.Fatal("truncated journal accepted")}
}
func TestNoSilentReenrollmentAndPinMismatch(t *testing.T) {
    path,keys,_:=setupState(t)
    g,err:=InitDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    if _,err:=InitDurableGuard(path,"machine-1",keys);!errors.Is(err,os.ErrExist) {t.Fatalf("re-enrollment was not rejected: %v",err)}
    if err:=g.Close();err!=nil {t.Fatal(err)}
    other,_,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil {t.Fatal(err)}
    if _,err:=OpenDurableGuard(path,"machine-1",map[string]ed25519.PublicKey{"admin":other});err==nil {t.Fatal("changed key accepted")}
    if _,err:=OpenDurableGuard(path,"other-machine",keys);err==nil {t.Fatal("wrong machine accepted")}
    opened,err:=OpenDurableGuard(path,"machine-1",keys);if err!=nil {t.Fatal(err)};defer opened.Close()
}
func TestJournalWritesFailClosed(t *testing.T) {
    path,keys,priv:=setupState(t)
    g,err:=InitDurableGuard(path,"machine-1",keys)
    if err!=nil {t.Fatal(err)}
    if err:=g.file.Close();err!=nil {t.Fatal(err)}
    now:=time.Now()
    if err:=g.Authorize(request(t,"abcdefghijklmnop",priv,now),now);err==nil {t.Fatal("authorized without journal sync")}
    if err:=g.Authorize(request(t,"different-nonce-1234",priv,now),now);err==nil {t.Fatal("poisoned state accepted")}
    _=g.Close()
}
