package sentinel

import (
 "encoding/xml"
 "errors"
 "fmt"
 "strconv"
 "strings"
 "time"
)

// FileAccessAudit is evidence emitted by Windows Security-Auditing 4663.
// It identifies a process that USED a write-capable FILE access right,
// not necessarily the author of every metadata change or a malicious actor.
// Windows must already have file-system auditing + the target SACL enabled.
type FileAccessAudit struct {
 RecordID uint64 `json:"record_id"`
 Time time.Time `json:"time"`
 ProcessID uint32 `json:"process_id,omitempty"`
 ProcessName string `json:"process_name,omitempty"`
 ObjectName string `json:"object_name"`
 AccessMask uint64 `json:"access_mask"`
}

const securityProvider = "Microsoft-Windows-Security-Auditing"
const securityChannel = "Security"
var ErrNotWriteFileAudit = errors.New("not a Windows Security write-capable file-access event")
const writeCapableMask uint64 = 0x2|0x4|0x10|0x40|0x100|0x10000

// ParseSecurity4663XML accepts only an explicit 4663 success audit from the
// Windows Security provider, with ObjectType=File and a write-capable access
// bit. System.Execution PID is intentionally ignored: the process fields are
// taken from the event's named EventData only, never inferred by filename.
func ParseSecurity4663XML(raw []byte)(FileAccessAudit,error){
 if len(raw)==0||len(raw)>64<<10{return FileAccessAudit{},errors.New("Security event size invalid")}
 var event defenderXML
 if err:=xml.Unmarshal(raw,&event);err!=nil{return FileAccessAudit{},fmt.Errorf("Security XML: %w",err)}
 if event.XMLName.Local!="Event" || event.System.Provider.Name!=securityProvider ||
   event.System.Channel!=securityChannel || event.System.EventID!=4663 ||
   event.System.RecordID==0{return FileAccessAudit{},ErrNotWriteFileAudit}
 when,err:=time.Parse(time.RFC3339Nano,event.System.TimeCreated.SystemTime)
 if err!=nil{return FileAccessAudit{},fmt.Errorf("Security 4663 time invalid: %w",err)}
 values:=make(map[string]string,len(event.EventData.Data))
 for _,v:=range event.EventData.Data {
  k:=normalizeEventField(v.Name)
  if k!=""{values[k]=strings.TrimSpace(v.Value)}
 }
 if values["objecttype"]!="File" || values["objectname"]=="" {return FileAccessAudit{},ErrNotWriteFileAudit}
 mask,err:=strconv.ParseUint(values["accessmask"],0,64)
 if err!=nil||mask&writeCapableMask==0 {return FileAccessAudit{},ErrNotWriteFileAudit}
 object:=boundedEventValue(values["objectname"])
 if normalWindowsPath(object)=="" {return FileAccessAudit{},ErrNotWriteFileAudit}
 audit:=FileAccessAudit{
  RecordID:event.System.RecordID,Time:when.UTC(),ObjectName:object,AccessMask:mask,
  ProcessName:boundedEventValue(values["processname"]),
 }
 // PID and full image path are recorded by Security-Auditing only when the
 // underlying audit policy and metadata supply them. A reused historical PID
 // must NEVER be used to terminate a currently running process.
 if n,err:=strconv.ParseUint(values["processid"],0,32);err==nil&&n>0{audit.ProcessID=uint32(n)}
 return audit,nil
}

// FileAuditCorrelation means the Windows audit record itself claims the
// given process exercised write-capable access against a watched file.
// It is not a claim of maliciousness or a causal link to a Sentinel burst.
func FileAuditCorrelation(e FileAccessAudit,root string)bool{
 return withinMonitoredRoot(e.ObjectName,root)
}
