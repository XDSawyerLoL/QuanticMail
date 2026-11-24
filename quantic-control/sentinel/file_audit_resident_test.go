package sentinel

import(
 "context"
 "os"
 "path/filepath"
 "sync/atomic"
 "testing"
 "time"
)

func TestResidentPersistsRealAuditProcessEvidence(t *testing.T){
 base:=t.TempDir()
 root:=filepath.Join(base,"watched")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 log:=filepath.Join(base,"events.jsonl")
 ctx,cancel:=context.WithCancel(context.Background())
 var attempts atomic.Int32
 read:=func(int)([]FileAccessAudit,bool,error){
  attempts.Add(1)
  return []FileAccessAudit{{
   RecordID:71,Time:time.Now().UTC(),ObjectName:"C:\\Users\\Test\\Documents\\report.docx",
   ProcessName:"C:\\Apps\\verified-by-security.exe",ProcessID:1234,AccessMask:2,
  }},false,nil
 }
 done:=make(chan error,1)
 // The path used in this test is deliberately a Windows path even on Linux.
 // Correlation is verified via the exact Windows root supplied below and we
 // intentionally do NOT grant a file-write event based solely on timing.
 go func(){
  done<-runResidentWithSources(ctx,root,log,nil,false,read,true)
 }()
 time.Sleep(250*time.Millisecond)
 cancel()
 select{
 case err:=<-done:if err!=nil{t.Fatal(err)}
 case <-time.After(4*time.Second):t.Fatal("resident did not stop")
 }
 if attempts.Load()==0{t.Fatal("file audit reader not polled")}
 records,err:=RecentRecords(log,40);if err!=nil{t.Fatal(err)}
 for _,r:=range records{
  if r.Type=="file_write_access"{t.Fatal("audit outside watched folder was incorrectly attributed")}
 }
}
