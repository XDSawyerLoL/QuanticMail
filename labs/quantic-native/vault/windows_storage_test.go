//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 "crypto/sha256"
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
