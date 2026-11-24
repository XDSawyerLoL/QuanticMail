//go:build windows

package vaultsession

import(
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
 "unsafe"
)

func TestGraphicalBrokerArgumentsRequirePinnedEnrollment(t *testing.T){
 pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 dir:=filepath.Clean(t.TempDir())
 pin:=strings.Repeat("a",64)
 cfg:=GraphicalBrokerConfig{Binary:filepath.Join(dir,"vault.exe"),BinarySHA256:pin,VaultDirectory:dir,SigningPin:pin,EncryptionPin:pin,RootPin:pin,MachineID:"test-machine",Controller:pub,Identity:Identity{Address:"test~"+strings.Repeat("a",32)+"@quantic",Device:"d-"+strings.Repeat("b",32),KEMPin:pin,DSAPin:pin}}
 args,err:=cfg.args()
 if err!=nil||len(args)!=10||args[0]!="--broker-windows-pq-quorum-gui-lab"{t.Fatalf("invalid fixed broker command: %v",err)}
 for _,mutate:=range []func(*GraphicalBrokerConfig){
  func(c *GraphicalBrokerConfig){c.Binary="relative.exe"},
  func(c *GraphicalBrokerConfig){c.RootPin=""},
  func(c *GraphicalBrokerConfig){c.Controller=nil},
  func(c *GraphicalBrokerConfig){c.VaultDirectory=dir+":stream"},
 }{
  c:=cfg;mutate(&c)
  if _,e:=c.args();e==nil{t.Fatal("untrusted enrollment accepted")}
 }
}
func TestGraphicalBrokerFilePinDeniesReplacement(t *testing.T){
 raw:=[]byte("inert test fixture; never executed")
 p:=filepath.Join(t.TempDir(),"fixture.exe")
 if err:=os.WriteFile(p,raw,0600);err!=nil{t.Fatal(err)}
 // CI TEMP may contain an 8.3 alias. Use the canonical long path
 // expected by trusted enrollment.
 ptr,err:=syscall.UTF16PtrFromString(p);if err!=nil{t.Fatal(err)}
 long:=make([]uint16,32768)
 n,_,_:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetLongPathNameW").Call(uintptr(unsafe.Pointer(ptr)),uintptr(unsafe.Pointer(&long[0])),uintptr(len(long)))
 if n==0||n>=uintptr(len(long)){t.Fatal("cannot resolve fixture path")}
 p=syscall.UTF16ToString(long[:n])
 if f,e:=pinGraphicalBroker(p,strings.Repeat("0",64));e==nil{f.Close();t.Fatal("incorrect binary hash accepted")}
 digest:=sha256.Sum256(raw)
 f,e:=pinGraphicalBroker(p,hex.EncodeToString(digest[:]));if e!=nil{t.Fatal(e)}
 defer f.Close()
 if w,e:=os.OpenFile(p,os.O_WRONLY,0600);e==nil{w.Close();t.Fatal("pinned executable permitted writing")}
 if e:=os.Rename(p,p+".replacement");e==nil{t.Fatal("pinned executable permitted rename")}
 if e:=f.Close();e!=nil{t.Fatal(e)}
 if e:=os.WriteFile(p,[]byte("released"),0600);e!=nil{t.Fatal(e)}
}
