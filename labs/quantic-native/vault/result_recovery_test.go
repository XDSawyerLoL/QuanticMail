//go:build linux

package main
import (
 "crypto/aes"
 "crypto/cipher"
 "os"
 "path/filepath"
 "testing"
)
func TestEncryptedRecoveryResult(t *testing.T){
 dir:=t.TempDir();if e:=os.Chmod(dir,0700);e!=nil{t.Fatal(e)}
 f,e:=os.Create(filepath.Join(dir,"journal"));if e!=nil{t.Fatal(e)};defer f.Close()
 j:=&replayLog{f:f,seen:map[[32]byte]bool{},anchorID:"test"}
 block,_:=aes.NewCipher(make([]byte,32));g,_:=cipher.NewGCM(block);p:=&pqKeys{recovery:g}
 k,req:=[32]byte{1},[32]byte{2};msg:="sensitive";r:=reply{OK:true,Message:&msg}
 if e=p.saveResult(j,k,req,r);e!=nil{t.Fatal(e)}
 if _,e=p.readResult(j,k,[32]byte{3});e==nil{t.Fatal("wrong request accepted")}
 got,e:=p.readResult(j,k,req);if e!=nil||got.Message==nil||*got.Message!=msg{t.Fatal("matching record refused")}
 if e=p.saveResult(j,k,req,r);e==nil{t.Fatal("overwritten")}
 path:=recoveryPath(j,k);raw,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)};raw[len(raw)-1]^=1
 if e=os.WriteFile(path,raw,0600);e!=nil{t.Fatal(e)}
 if _,e=p.readResult(j,k,req);e==nil{t.Fatal("tampered recovery accepted")}
}
