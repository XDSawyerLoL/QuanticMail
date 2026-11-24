package sentinel

import(
 "context"
 "fmt"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"
)
func TestResidentWritesDurableStartStop(t *testing.T){
 dir:=t.TempDir()
 root:=filepath.Join(dir,"observed")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 log:=filepath.Join(dir,"sentinel.jsonl")
 ctx,cancel:=context.WithCancel(context.Background())
 done:=make(chan error,1)
 go func(){done<-RunResident(ctx,root,log)}()
 time.Sleep(200*time.Millisecond)
 for i:=0;i<25;i++{name:=filepath.Join(root,fmtName(i));if err:=os.WriteFile(name,[]byte("user test"),0600);err!=nil{t.Fatal(err)}}
 time.Sleep(3*time.Second)
 cancel()
 select{case err:=<-done:if err!=nil{t.Fatal(err)};case <-time.After(7*time.Second):t.Fatal("agent did not stop")}
 records,err:=RecentRecords(log,30);if err!=nil{t.Fatal(err)}
 seenStart,seenStop,seenAlert:=false,false,false
 for _,r:=range records{
  switch r.Type{case "started":seenStart=true;case "stopped":seenStop=true;case "alert":seenAlert=true}
 }
 if !seenStart||!seenStop||!seenAlert{t.Fatalf("missing durable agent lifecycle or alert: %+v",records)}
}
func fmtName(i int)string{return fmt.Sprintf("file-%03d.txt",i)}
func TestAuditRejectsCorruptionAndSymlinks(t *testing.T){
 dir:=t.TempDir()
 file:=filepath.Join(dir,"log")
 a,err:=openAudit(file);if err!=nil{t.Fatal(err)}
 if err:=a.Append(Record{Type:"started"});err!=nil{t.Fatal(err)}
 if err:=a.Close();err!=nil{t.Fatal(err)}
 records,err:=RecentRecords(file,10);if err!=nil||len(records)!=1{t.Fatalf("read: %v %v",records,err)}
 if err:=os.WriteFile(file,[]byte("not JSON\n"),0600);err!=nil{t.Fatal(err)}
 if _,err:=RecentRecords(file,10);err==nil{t.Fatal("tampered log accepted")}
 if err:=os.Remove(file);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(dir,file);err==nil{
  if _,err:=openAudit(file);err==nil{t.Fatal("symlink accepted")}
 }
 if _,err:=RecentRecords(filepath.Join(dir,"missing"),10);!errors.Is(err,os.ErrNotExist){t.Fatal("missing log not rejected")}
}
func TestMissingRootStopsResident(t *testing.T){
 dir:=t.TempDir()
 root:=filepath.Join(dir,"does-not-exist")
 log:=filepath.Join(dir,"alerts.jsonl")
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
 defer cancel()
 if err:=RunResident(ctx,root,log);err==nil{t.Fatal("invalid watched folder incorrectly accepted")}
}
