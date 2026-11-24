//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 "crypto/sha256"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/x509"
 "encoding/pem"
 "encoding/binary"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsPrivateStorage(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"vault-private")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 if e:=winCreatePrivateDirectory(dir);e==nil{t.Fatal("directory reused")}
 path:=filepath.Join(dir,"vault");pw:=[]byte("synthetic classical storage password")
 k,e:=freshPortable();if e!=nil{t.Fatal(e)}
 s,a:=portablePins(k)
 if e=winWriteClassical(path,portableMagic,pw,k);e!=nil{t.Fatal(e)}
 if e=winWriteClassical(path,portableMagic,pw,k);e==nil{t.Fatal("overwritten")}
 opened,e:=winReadClassical(path,portableMagic,pw,s,a);if e!=nil{t.Fatal(e)}
 expected,actual:=portablePins(opened);if expected!=s||actual!=a{t.Fatal("changed pins")}
 if _,e=winReadClassical(path,portableMagic,[]byte("synthetic invalid password"),s,a);e==nil{t.Fatal("wrong password")}
 if _,e=winReadClassical(path,portableMagic,pw,strings.Repeat("f",64),a);e==nil{t.Fatal("wrong pin")}
 raw,e:=winReadPrivate(path,4096);if e!=nil{t.Fatal(e)}
 if bytes.Contains(raw,k.agreement.Bytes()){t.Fatal("plaintext")}
 link:=filepath.Join(dir,"hardlink")
 if e=os.Link(path,link);e!=nil{t.Fatal(e)}
 if _,e=winReadPrivate(path,4096);e==nil{t.Fatal("hardlink accepted")}
 if e=os.Remove(link);e!=nil{t.Fatal(e)}
 // Explicitly weaken only this synthetic file and check that the handle ACL is refused.
 if b,e:=exec.Command("icacls",path,"/grant","*S-1-1-0:(R)").CombinedOutput();e!=nil{t.Fatal("ACL setup",e,string(b))}
 if _,e=winReadPrivate(path,4096);e==nil{t.Fatal("broad ACL accepted")}
 junction:=filepath.Join(filepath.Dir(dir),"junction")
 if b,e:=exec.Command("cmd.exe","/d","/c","mklink","/J",junction,dir).CombinedOutput();e!=nil{t.Fatal("junction setup",e,string(b))}
 defer os.Remove(junction)
 if _,e:=winLockDirectory(junction,true);e==nil{t.Fatal("junction accepted")}
 if _,_,e:=winPathParts(path+":secret");e==nil{t.Fatal("ADS accepted")}
}
func TestWindowsPQStorageReopen(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"pq-private")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{t.Fatal(e)}
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{kem.close();t.Fatal(e)}
 p,e:=pqMake(kem,dsa,"alice~"+strings.Repeat("a",32)+"@quantic","d-"+strings.Repeat("b",32))
 if e!=nil{kem.close();dsa.close();t.Fatal(e)}
 addr,device,kpin,dpin:=p.address,p.device,p.kemPin,p.dsaPin
 magic,e:=pqBinding(strings.Repeat("1",64),strings.Repeat("2",64),strings.Repeat("3",64),strings.Repeat("4",64),addr,device)
 if e!=nil{p.close();t.Fatal(e)}
 pw:=[]byte("synthetic pq storage password only")
 f:=filepath.Join(dir,"pq-sidecar")
 e=winWritePQ(f,magic,pw,p);p.close();if e!=nil{t.Fatal(e)}
 q,e:=winReadPQ(f,magic,pw,addr,device,kpin,dpin);if e!=nil{t.Fatal(e)};defer q.close()
 ct,secret,e:=pqEncapPublic(q.kemPub);if e!=nil{t.Fatal(e)};defer clear(secret)
 got,e:=q.kem.dec(ct);if e!=nil||!bytes.Equal(secret,got){t.Fatal("decapsulation",e)};defer clear(got)
 msg:=sha256.Sum256([]byte("synthetic restart storage"))
 sig,e:=q.dsa.sign(msg[:]);if e!=nil||!pqVerifyRoot(q.dsaPub,msg[:],sig){t.Fatal("signature",e)}
 if _,e=winReadPQ(f,magic+"x",pw,addr,device,kpin,dpin);e==nil{t.Fatal("wrong binding")}
 if _,e=winReadPQ(f,magic,[]byte("synthetic wrong password"),addr,device,kpin,dpin);e==nil{t.Fatal("wrong password")}
 raw,e:=winReadPrivate(f,50000);if e!=nil{t.Fatal(e)}
 raw[len(raw)-1]^=1
 if e=os.WriteFile(f,raw,0600);e!=nil{t.Fatal(e)}
 if _,e=winReadPQ(f,magic,pw,addr,device,kpin,dpin);e==nil{t.Fatal("tamper accepted")}
}

func TestWindowsProtectedDraftAtRest(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"draft-private")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 path:=filepath.Join(dir,"draft-synthetic.json")
 plain:=[]byte("{\"body\":\"synthetic secret draft marker\"}")
 if e:=winWriteProtectedDraft(path,plain);e!=nil{t.Fatal(e)}
 raw,e:=winReadPrivate(path,32768);if e!=nil{t.Fatal(e)}
 if !bytes.HasPrefix(raw,[]byte(draftMagic))||bytes.Contains(raw,plain)||bytes.Contains(raw,[]byte("synthetic secret draft marker")){t.Fatal("plaintext draft persisted")}
 opened,e:=winReadProtectedDraft(path);if e!=nil||!bytes.Equal(opened,plain){t.Fatal("roundtrip",e)};clear(opened)
 if e=winWriteProtectedDraft(path,plain);e==nil{t.Fatal("overwrite accepted")}
 other:=filepath.Join(dir,"draft-other.json")
 if e=winWritePrivate(other,raw);e!=nil{t.Fatal(e)}
 if _,e=winReadProtectedDraft(other);e==nil{t.Fatal("copied ciphertext accepted under different name")}
 raw[len(raw)-1]^=1
 if e=os.WriteFile(path,raw,0600);e!=nil{t.Fatal(e)}
 if _,e=winReadProtectedDraft(path);e==nil{t.Fatal("tampering accepted")}
 legacy:=filepath.Join(dir,"draft-legacy.json")
 if e=winWritePrivate(legacy,plain);e!=nil{t.Fatal(e)}
 if _,e=winReadProtectedDraft(legacy);e==nil{t.Fatal("plaintext fallback accepted")}
 retained,e:=winReadPrivate(legacy,8192);if e!=nil||!bytes.Equal(retained,plain){t.Fatal("historical file changed")}
}

func TestWindowsLocalSecretProtection(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"secret-private")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 plain:=bytes.Repeat([]byte{0x42},32)
 path:=filepath.Join(dir,"receipt.key")
 if e:=winWriteLocalSecret(path,plain);e!=nil{t.Fatal(e)}
 raw,e:=winReadPrivate(path,32768);if e!=nil{t.Fatal(e)}
 if !bytes.HasPrefix(raw,[]byte(localSecretMagic))||bytes.Contains(raw,plain){t.Fatal("receipt key stored in clear")}
 opened,e:=winReadLocalSecret(path);if e!=nil||!bytes.Equal(opened,plain){t.Fatal("roundtrip",e)};clear(opened)
 if e=winWriteLocalSecret(path,plain);e==nil{t.Fatal("overwrite")}
 other:=filepath.Join(dir,"controller.pem")
 if e=winWritePrivate(other,raw);e!=nil{t.Fatal(e)}
 if _,e=winReadLocalSecret(other);e==nil{t.Fatal("cross-file ciphertext accepted")}
 raw[len(raw)-1]^=1
 if e=os.WriteFile(path,raw,0600);e!=nil{t.Fatal(e)}
 if _,e=winReadLocalSecret(path);e==nil{t.Fatal("tamper accepted")}
 if e=os.WriteFile(other,plain,0600);e!=nil{t.Fatal(e)}
 if _,e=winReadLocalSecret(other);e==nil{t.Fatal("legacy plaintext fallback")}
 retained,e:=winReadPrivate(other,4096);if e!=nil||!bytes.Equal(retained,plain){t.Fatal("legacy secret changed")}
}

func TestWindowsControllerCustody(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"custody")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)};defer clear(key)
 der,e:=x509.MarshalPKCS8PrivateKey(key);if e!=nil{t.Fatal(e)};defer clear(der)
 raw:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der});defer clear(raw)
 if e=winWriteLocalSecret(filepath.Join(dir,"controller.pem"),raw);e!=nil{t.Fatal(e)}
 if e=winWritePrivate(filepath.Join(dir,"lab-provisioned"),[]byte(hexHash(pub)));e!=nil{t.Fatal(e)}
 if handled,e:=winClientIO([]string{"vault","--windows-client-read-lab",dir,"controller.pem"});!handled||e==nil{t.Fatal("controller export allowed")}
 nonce:=bytes.Repeat([]byte{7},32)
 frame:=make([]byte,36);copy(frame,nonce);binary.BigEndian.PutUint32(frame[32:],1)
 body:=[]byte("{\"op\":\"public\"}")
 sig,e:=winControllerFrameSign(dir,append(frame,body...));if e!=nil{t.Fatal(e)}
 d:=appDigest(nonce,1,body);if !ed25519.Verify(pub,d[:],sig){t.Fatal("frame signature mismatch")}
 for _,bad:=range [][]byte{nil,append(frame,[]byte("{\"op\":\"arbitrary-sign\"}")...),append(frame,[]byte("{\"op\":\"public\",\"unknown\":true}")...)}{
  if _,e=winControllerFrameSign(dir,bad);e==nil{t.Fatal("invalid frame signed")}
 }
}
