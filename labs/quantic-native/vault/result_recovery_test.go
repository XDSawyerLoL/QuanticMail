//go:build linux

package main
import (
 "crypto/aes"
 "crypto/cipher"
 "errors"
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

func TestAuthorizedMailResultReservationAndRecovery(t *testing.T){
 for _,refused:=range []int{0,1,2}{
  t.Run(string(rune('0'+refused)),func(t *testing.T){
   path,s,e,app:=testJournal(t);j,err:=openReplay(path,s,e,app);if err!=nil{t.Fatal(err)};defer j.close()
   id,_:=anchorID(s,e,app);q:=&quorumAnchor{};var ws [4]*fakeAnchor
   for i:=range ws{ws[i]=&fakeAnchor{tail:j.tail};q.members[i]=ws[i]}
   if err=j.attachAnchor(q,id);err!=nil{t.Fatal(err)}
   for i:=0;i<refused;i++{ws[i].fail=true}
   block,_:=aes.NewCipher(make([]byte,32));g,_:=cipher.NewGCM(block);p:=&pqKeys{recovery:g}
   k,req:=[32]byte{1},[32]byte{2};msg:="synthetic";calls:=0
   op:=func()(reply,error){calls++;if !j.seen[k]{t.Fatal("provider reached before reservation")};n:=0;for _,w:=range ws{if w.count==1&&w.tail==j.tail{n++}};if n<3{t.Fatal("quorum not committed")};return reply{OK:true,Message:&msg},nil}
   if _,err=p.authorizedMailResult(j,k,req,true,op);err==nil||calls!=0{t.Fatal("uncommitted recovery")}
   r,err:=p.authorizedMailResult(j,k,req,false,op)
   if refused==2{if err==nil||calls!=0||!j.failed{t.Fatal("refused quorum reached provider")};return}
   if err!=nil||r.Message==nil||*r.Message!=msg||calls!=1{t.Fatal("valid operation failed",err)}
   if _,err=p.authorizedMailResult(j,k,req,false,op);err==nil||calls!=1{t.Fatal("duplicate private call")}
   if _,err=p.authorizedMailResult(j,k,[32]byte{3},true,op);err==nil||calls!=1{t.Fatal("changed recovery")}
   r,err=p.authorizedMailResult(j,k,req,true,op);if err!=nil||r.Message==nil||*r.Message!=msg||calls!=1||len(j.seen)!=1{t.Fatal("exact recovery failed",err)}
  })
 }
}
func TestAuthorizedMailResultProviderFailureBurnsReservation(t *testing.T){
 path,s,e,app:=testJournal(t);j,err:=openReplay(path,s,e,app);if err!=nil{t.Fatal(err)};defer j.close()
 id,_:=anchorID(s,e,app);a:=&fakeAnchor{tail:j.tail};if err=j.attachAnchor(a,id);err!=nil{t.Fatal(err)}
 block,_:=aes.NewCipher(make([]byte,32));g,_:=cipher.NewGCM(block);p:=&pqKeys{recovery:g}
 k,req:=[32]byte{1},[32]byte{2};calls:=0
 op:=func()(reply,error){calls++;return reply{},errors.New("synthetic provider failure")}
 if _,err=p.authorizedMailResult(j,k,req,false,op);err==nil||calls!=1||!j.seen[k]{t.Fatal("reservation lost")}
 if _,err=p.authorizedMailResult(j,k,req,false,op);err==nil||calls!=1{t.Fatal("retry invoked provider")}
 if _,err=p.authorizedMailResult(j,k,req,true,op);err==nil||calls!=1{t.Fatal("missing result recovered")}
}
