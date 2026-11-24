package sentinel

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "time"
)

const maxEventLogBytes=4<<20
const maxRecentReadBytes=4<<20
type Record struct{
 Time time.Time `json:"time"`
 Type string `json:"type"`
 Message string `json:"message,omitempty"`
 Alert *Alert `json:"alert,omitempty"`
 Defender *DefenderCFAEvent `json:"defender,omitempty"`
 FileAudit *FileAccessAudit `json:"file_audit,omitempty"`
 Evidence string `json:"evidence,omitempty"`
 Advice string `json:"advice,omitempty"`
}

type localAudit struct{file *os.File;path string;size int64}
func openAudit(path string)(*localAudit,error){
 if !filepath.IsAbs(path){return nil,errors.New("absolute audit path required")}
 parent:=filepath.Dir(path)
 stat,err:=os.Stat(parent);if err!=nil||!stat.IsDir(){return nil,errors.New("audit folder not available")}
 before,err:=os.Lstat(path)
 if err!=nil&&!errors.Is(err,os.ErrNotExist){return nil,err}
 if err==nil&&(!before.Mode().IsRegular()||before.Size()>maxEventLogBytes){return nil,errors.New("audit file invalid or full")}
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_APPEND,0600)
 if err!=nil{return nil,err}
 after,err:=f.Stat()
 if err!=nil||!after.Mode().IsRegular()||(before!=nil&&!os.SameFile(before,after)){
  f.Close();return nil,errors.New("audit file changed during open")
 }
 return &localAudit{file:f,path:path,size:after.Size()},nil
}
func (a *localAudit) Close()error{
 if a==nil||a.file==nil{return nil}
 err:=a.file.Close();a.file=nil;return err
}
func (a *localAudit) Append(r Record)error{
 if a==nil||a.file==nil{return errors.New("audit closed")}
 if r.Type==""{return errors.New("event type required")}
 if r.Time.IsZero(){r.Time=time.Now().UTC()}
 if r.Message!=""&&len(r.Message)>512{r.Message=r.Message[:512]}
 if len(r.Evidence)>512 {r.Evidence=r.Evidence[:512]}
 if len(r.Advice)>512 {r.Advice=r.Advice[:512]}
 if r.FileAudit!=nil{
  cp:=*r.FileAudit
  if len(cp.ProcessName)>512{cp.ProcessName=cp.ProcessName[:512]}
  if len(cp.ObjectName)>512{cp.ObjectName=cp.ObjectName[:512]}
  r.FileAudit=&cp
 }
 if r.Defender!=nil{
  cp:=*r.Defender
  if len(cp.ProcessPath)>512{cp.ProcessPath=cp.ProcessPath[:512]}
  if len(cp.TargetPath)>512{cp.TargetPath=cp.TargetPath[:512]}
  r.Defender=&cp
 }
 if r.Alert!=nil{
  cp:=*r.Alert
  if len(cp.Example)>512{cp.Example=cp.Example[:512]}
  r.Alert=&cp
 }
 raw,err:=json.Marshal(r);if err!=nil{return err}
 raw=append(raw,'\n')
 if a.size+int64(len(raw))>maxEventLogBytes{return errors.New("audit log full: monitoring stopped")}
 n,err:=a.file.Write(raw)
 if err!=nil{return err}
 if n!=len(raw){return io.ErrShortWrite}
 if err:=a.file.Sync();err!=nil{return err}
 a.size+=int64(n)
 return nil
}

// RunResident continuously observes an explicitly configured directory until
// cancelled. No elevated privileges, network connections, or destructive
// actions are used. Every alert is durably recorded before processing more.
func RunResident(ctx context.Context,root,logPath string)error{
 return runResidentWithSources(ctx,root,logPath,ReadRecentCFA,runtime.GOOS=="windows",ReadRecentFileAudits,runtime.GOOS=="windows")
}

// RunResidentWithBackupReport records a startup observation, not a live
// guarantee. The caller owns the actual backup handles until agent exit.
func RunResidentWithBackupReport(ctx context.Context,root,logPath string,requested,held int,backupErr error)error{
 record:=Record{Type:"backup_locks_active",Message:fmt.Sprintf("%d/%d verrous de sauvegarde acquis au démarrage",held,requested)}
 if backupErr!=nil||held!=requested{record=Record{Type:"backup_locks_failed",Message:"Verrous de sauvegarde non acquis : vérifier les copies sélectionnées."}}
 return runResidentWithSources(ctx,root,logPath,ReadRecentCFA,runtime.GOOS=="windows",ReadRecentFileAudits,runtime.GOOS=="windows",record)
}

// runResidentWithDefender makes the native event-log source replaceable by a
// test double, without exposing an API for untrusted code to inject events
// into the installed agent. Only RunResident is called by the Windows binary.
func runResidentWithDefender(ctx context.Context,root,logPath string,reader CFAReader,enabled bool)error{
 return runResidentWithSources(ctx,root,logPath,reader,enabled,nil,false)
}

func runResidentWithSources(ctx context.Context,root,logPath string,reader CFAReader,enabled bool,
 fileAuditReader FileAuditReader,fileAuditEnabled bool,startup ...Record)error{
 if ctx==nil{return errors.New("context required")}
 audit,err:=openAudit(logPath)
 if err!=nil{return err}
 defer audit.Close()
 if err:=audit.Append(Record{Type:"started",Message:"Surveillance locale démarrée"});err!=nil{return err}
 for _,record:=range startup{if err:=audit.Append(record);err!=nil{return err}}
 events:=make(chan Event,256)
 watchCtx,cancel:=context.WithCancel(ctx)
 defer cancel()
 watchDone:=make(chan error,1)
 go func(){watchDone<-Watch(watchCtx,root,events);close(events)}()
 detector:=NewDetector(DefaultPolicy())
 heartbeat:=time.NewTicker(time.Minute)
 defer heartbeat.Stop()
 var fileAudits <-chan FileAuditNotice
 if fileAuditEnabled && fileAuditReader!=nil{
  changes:=make(chan FileAuditNotice,64)
  fileAudits=changes
  go func(){
   defer close(changes)
   MonitorFileAccessAudits(watchCtx,time.Now().UTC(),15*time.Second,root,fileAuditReader,changes)
  }()
 }
 var received uint64
 var lastFileAlert *Alert
 // Only Windows can read the local Defender Operational journal. No remote
 // subscription or privileged Event Log configuration is performed.
 var defenderNotices <-chan DefenderNotice
 if enabled {
  notices:=make(chan DefenderNotice,64)
  defenderNotices=notices
  go func(){
   defer close(notices)
   MonitorDefenderEvents(watchCtx,time.Now().UTC(),10*time.Second,reader,notices)
  }()
 }
 for{
  select{
  case <-ctx.Done():
   cancel()
   select{case <-watchDone:case <-time.After(5*time.Second):}
   _=audit.Append(Record{Type:"stopped",Message:"Surveillance arrêtée à la demande"})
   return nil
  case err:=<-watchDone:
   if err!=nil{
    _=audit.Append(Record{Type:"error",Message:err.Error()})
    return fmt.Errorf("watcher unavailable: %w",err)
   }
   return nil
  case ev,ok:=<-events:
   if !ok{events=nil;continue}
   received++
   if alert:=detector.Observe(ev);alert!=nil{
    lastFileAlert=alert
    if err:=audit.Append(Record{Type:"alert",Message:alert.Rule,Alert:alert});err!=nil{return err}
   }
  case notice,ok:=<-defenderNotices:
   if !ok{defenderNotices=nil;continue}
   switch{
   case notice.Err!=nil:
    if err:=audit.Append(Record{Type:"defender_unavailable",Message:notice.Err.Error()});err!=nil{return err}
   case notice.Restored:
    if err:=audit.Append(Record{Type:"defender_restored",Message:"Accès au journal Defender rétabli"});err!=nil{return err}
   case notice.Overflow:
    if err:=audit.Append(Record{Type:"defender_incomplete",Message:"Flux CFA supérieur à la limite de lecture : certains événements peuvent manquer"});err!=nil{return err}
   case notice.Event!=nil:
    cf:=CorrelateCFAEvent(*notice.Event,root,lastFileAlert)
    process:="processus non indiqué"
    if notice.Event.ProcessPath!="" {process="processus indiqué par Defender : "+notice.Event.ProcessPath}
    message:=fmt.Sprintf("Defender CFA %d (%s), %s",notice.Event.EventID,notice.Event.Outcome,process)
    if err:=audit.Append(Record{
      Time:notice.Event.Time,Type:"defender_cfa",Message:message,
      Defender:notice.Event,Evidence:cf.Evidence,Advice:cf.RecommendedAction,
    });err!=nil{return err}
   }
  case notice,ok:=<-fileAudits:
   if !ok{fileAudits=nil;continue}
   switch{
   case notice.Err!=nil:
    if err:=audit.Append(Record{Type:"file_audit_unavailable",Message:notice.Err.Error()});err!=nil{return err}
   case notice.Restored:
    if err:=audit.Append(Record{Type:"file_audit_restored",Message:"Audit Security 4663 de nouveau accessible"});err!=nil{return err}
   case notice.Overflow:
    if err:=audit.Append(Record{Type:"file_audit_incomplete",Message:"Journal 4663 trop actif : preuves possiblement manquantes"});err!=nil{return err}
   case notice.Event!=nil:
    e:=notice.Event
    process:="Programme non indiqué par Windows"
    if e.ProcessName!=""{process=e.ProcessName}
    evidence:="Audit Windows 4663 : droit d'accès compatible écriture utilisé ; pas une preuve de modification ou de malveillance"
    if lastFileAlert!=nil&&absDuration(lastFileAlert.Time.Sub(e.Time))<=30*time.Second{
     evidence+=" ; proche d'une alerte de fichiers (lien causal non démontré)"
    }
    if err:=audit.Append(Record{
     Time:e.Time,Type:"file_write_access",FileAudit:e,
     Message:"Accès selon Windows Security : "+process,
     Evidence:evidence,
     Advice:"Examiner l'application dans les propriétés du fichier et dans Sécurité Windows ; ne pas terminer un PID historique",
    });err!=nil{return err}
   }
  case <-heartbeat.C:
   if err:=audit.Append(Record{Type:"heartbeat",Message:fmt.Sprintf("%d événements détectés",received)});err!=nil{return err}
  }
 }
}

// RecentRecords allows GUI display without loading an unbounded/untrusted log.
// It does not grant a local attacker tamper-proof audit guarantees.
func RecentRecords(path string,limit int)([]Record,error){
 if limit<1||limit>100{return nil,errors.New("invalid recent record count")}
 before,err:=os.Lstat(path);if err!=nil{return nil,err}
 if !before.Mode().IsRegular()||before.Size()>maxRecentReadBytes{return nil,errors.New("invalid audit log")}
 raw,err:=os.ReadFile(path);if err!=nil{return nil,err}
 lines:=strings.Split(strings.TrimSuffix(string(raw),"\n"),"\n")
 if len(lines)>limit{lines=lines[len(lines)-limit:]}
 records:=make([]Record,0,len(lines))
 for _,line:=range lines{
  if line==""{continue}
  var r Record
  if len(line)>8192||json.Unmarshal([]byte(line),&r)!=nil{return nil,errors.New("corrupt audit record")}
  records=append(records,r)
 }
 return records,nil
}
