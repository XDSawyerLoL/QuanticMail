package sentinel

import(
 "context"
 "errors"
 "sync/atomic"
 "testing"
 "time"
)

func TestFileAuditMonitorRealSourceFieldsAndDedup(t *testing.T){
 start:=time.Now().Add(-time.Second)
 var calls atomic.Int32
 read:=func(limit int)([]FileAccessAudit,bool,error){
  calls.Add(1)
  if limit!=64{t.Error("unbounded audit read")}
  return []FileAccessAudit{
   {RecordID:11,Time:time.Now(),ObjectName:"C:\\Users\\Test\\Documents\\one.txt",ProcessName:"C:\\Apps\\writer.exe",ProcessID:1532,AccessMask:2},
   {RecordID:12,Time:time.Now(),ObjectName:"C:\\Users\\Test\\Other\\two.txt",ProcessName:"C:\\Apps\\writer.exe",AccessMask:2},
   {RecordID:10,Time:start.Add(-time.Hour),ObjectName:"C:\\Users\\Test\\Documents\\old.txt",AccessMask:2},
  },false,nil
 }
 ctx,cancel:=context.WithTimeout(context.Background(),120*time.Millisecond);defer cancel()
 out:=make(chan FileAuditNotice,32)
 MonitorFileAccessAudits(ctx,start,15*time.Millisecond,"C:\\Users\\Test\\Documents",read,out)
 close(out)
 count:=0
 for n:=range out{
  if n.Event!=nil{
   count++
   if n.Event.ProcessID!=1532||n.Event.RecordID!=11{t.Fatalf("incorrect process source: %+v",n.Event)}
  }
 }
 if calls.Load()<3||count!=1{t.Fatalf("polls %d events %d",calls.Load(),count)}
}
func TestFileAuditMonitorFailsVisiblyAndRecovers(t *testing.T){
 start:=time.Now().Add(-time.Second)
 var calls atomic.Int32
 read:=func(int)([]FileAccessAudit,bool,error){
  if calls.Add(1)==1{return nil,false,errors.New("access denied")}
  return []FileAccessAudit{{RecordID:1,Time:time.Now(),ObjectName:"C:\\Test\\a",AccessMask:2}},false,nil
 }
 ctx,cancel:=context.WithTimeout(context.Background(),70*time.Millisecond);defer cancel()
 out:=make(chan FileAuditNotice,32)
 MonitorFileAccessAudits(ctx,start,10*time.Millisecond,"C:\\Test",read,out)
 close(out)
 fail,restored,records:=0,0,0
 for n:=range out{
  if n.Err!=nil{fail++}
  if n.Restored{restored++}
  if n.Event!=nil{records++}
 }
 if fail!=1||restored!=1||records!=1{t.Fatalf("failure=%d recovery=%d records=%d",fail,restored,records)}
}
