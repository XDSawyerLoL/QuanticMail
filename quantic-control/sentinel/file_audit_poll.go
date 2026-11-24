package sentinel

import (
 "context"
 "fmt"
 "sort"
 "time"
)

type FileAuditReader func(limit int)([]FileAccessAudit,bool,error)
type FileAuditNotice struct{
 Event *FileAccessAudit
 Err error
 Restored bool
 Overflow bool
}

// MonitorFileAccessAudits reports only records for the explicitly watched
// folder. It is an optional read-only consumer of OS-generated Security 4663
// events: Windows audit policy and file SACL must be set independently.
// Missing privileges produce an explicit error, never invented attribution.
func MonitorFileAccessAudits(ctx context.Context,started time.Time,interval time.Duration,
 root string,reader FileAuditReader,out chan<-FileAuditNotice){
 if ctx==nil||reader==nil||out==nil{return}
 if interval<=0{interval=15*time.Second}
 tick:=time.NewTicker(interval);defer tick.Stop()
 seen:=make(map[uint64]struct{},128)
 wasUnavailable:=false
 lastOverflow:=time.Time{}
 send:=func(n FileAuditNotice)bool{
  select{case <-ctx.Done():return false;case out<-n:return true}
 }
 poll:=func()bool{
  events,truncated,err:=reader(64)
  if err!=nil{
   if !wasUnavailable {
    if !send(FileAuditNotice{Err:fmt.Errorf("Windows Security 4663 unavailable: %w",err)}){return false}
   }
   wasUnavailable=true
   return true
  }
  if wasUnavailable{
   if !send(FileAuditNotice{Restored:true}){return false}
   wasUnavailable=false
  }
  sort.Slice(events,func(i,j int)bool{
   if events[i].Time.Equal(events[j].Time){return events[i].RecordID<events[j].RecordID}
   return events[i].Time.Before(events[j].Time)
  })
  if truncated&&len(events)>0&&!events[0].Time.Before(started)&&
    (lastOverflow.IsZero()||time.Since(lastOverflow)>time.Minute){
   if !send(FileAuditNotice{Overflow:true}){return false}
   lastOverflow=time.Now()
  }
  for _,e:=range events{
   if e.Time.Before(started)||e.Time.After(time.Now().Add(5*time.Second)){continue}
   if !FileAuditCorrelation(e,root){continue}
   if _,ok:=seen[e.RecordID];ok{continue}
   seen[e.RecordID]=struct{}{}
   copy:=e
   if !send(FileAuditNotice{Event:&copy}){return false}
  }
  if len(seen)>256{
   seen=make(map[uint64]struct{},128)
   for _,e:=range events{
    if FileAuditCorrelation(e,root){seen[e.RecordID]=struct{}{}}
   }
  }
  return true
 }
 if ctx.Err()!=nil||!poll(){return}
 for{
  select{
  case <-ctx.Done():return
  case <-tick.C:if !poll(){return}
  }
 }
}
