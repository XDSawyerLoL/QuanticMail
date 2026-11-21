//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsRecoveryExactResult(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"private")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 path:=filepath.Join(dir,"journal.log")
 s,a,c:=strings.Repeat("a",64),strings.Repeat("b",64),strings.Repeat("c",64)
 if e:=winInitReplay(path,s,a,c);e!=nil{t.Fatal(e)}
 j,e:=winOpenReplay(path,s,a,c);if e!=nil{t.Fatal(e)}
 id,e:=anchorID(s,a,c);if e!=nil{j.close();t.Fatal(e)}
 j.anchorID=id
 block,_:=aes.NewCipher(make([]byte,32));g,_:=cipher.NewGCM(block);p:=&pqKeys{recovery:g}
 k,req:=[32]byte{1},[32]byte{2};msg:="synthetic sensitive result"
 r:=reply{OK:true,Message:&msg}
 if e=p.saveResult(j,k,req,r);e!=nil{j.close();t.Fatal(e)}
 if e=j.consume(k);e!=nil{j.close();t.Fatal(e)}
 j.close()
 j,e=winOpenReplay(path,s,a,c);if e!=nil{t.Fatal(e)};defer j.close();j.anchorID=id
 if !j.has(k){t.Fatal("replay lost")}
 got,e:=p.readResult(j,k,req);if e!=nil||got.Message==nil||*got.Message!=msg{t.Fatal("recovery",e)}
 if _,e=p.readResult(j,k,[32]byte{3});e==nil{t.Fatal("wrong request")}
 if e=p.saveResult(j,k,req,r);e==nil{t.Fatal("overwritten")}
 cache:=recoveryPath(j,k);raw,e:=winReadPrivate(cache,recoveryMax);if e!=nil{t.Fatal(e)}
 if bytes.Contains(raw,[]byte(msg)){t.Fatal("plaintext")}
 raw[len(raw)-1]^=1
 if e=os.WriteFile(cache,raw,0600);e!=nil{t.Fatal(e)}
 if _,e=p.readResult(j,k,req);e==nil{t.Fatal("tamper")}
}
func TestWindowsQuorumConfigRefusal(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"private")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 if _,e:=winLoadQuorum(dir);e==nil{t.Fatal("missing quorum")}
 if e:=winWritePrivate(filepath.Join(dir,"quorum.json"),[]byte("[]"));e!=nil{t.Fatal(e)}
 if _,e:=winLoadQuorum(dir);e==nil{t.Fatal("empty quorum")}
 if e:=winAttachPQ(nil,nil,nil,"","");e==nil{t.Fatal("missing authority")}
}
