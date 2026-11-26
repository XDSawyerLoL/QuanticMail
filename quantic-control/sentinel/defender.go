package sentinel

import (
    "encoding/xml"
    "errors"
    "fmt"
    "strconv"
    "strings"
    "time"
)

// DefenderCFAEvent describes a read-only Controlled Folder Access (CFA)
// event produced by Microsoft Defender. The source is Defender's event log,
// NOT the metadata-only Sentinel folder scanner.
type DefenderCFAEvent struct {
    RecordID uint64
    EventID int
    Time time.Time
    Outcome string
    ProcessPath string
    TargetPath string
    ProcessID uint32 // ONLY an explicit EventData process-id field, never System.Execution.
}

type defenderXML struct {
    XMLName xml.Name `xml:"Event"`
    System struct {
        Provider struct {Name string `xml:"Name,attr"`} `xml:"Provider"`
        Channel string `xml:"Channel"`
        EventID int `xml:"EventID"`
        RecordID uint64 `xml:"EventRecordID"`
        TimeCreated struct {SystemTime string `xml:"SystemTime,attr"`} `xml:"TimeCreated"`
    } `xml:"System"`
    EventData struct {
        Data []struct {
            Name string `xml:"Name,attr"`
            Value string `xml:",chardata"`
        } `xml:"Data"`
    } `xml:"EventData"`
}

const defenderChannel = "Microsoft-Windows-Windows Defender/Operational"
const defenderProvider = "Microsoft-Windows-Windows Defender"

func cfaOutcome(eventID int) string {
    switch eventID {
    case 1123,1127: return "blocked"
    case 1124,1128: return "audited"
    default: return ""
    }
}
func normalizeEventField(s string)string{
    return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s)," ",""),"_",""))
}
func boundedEventValue(s string)string{
    s=strings.TrimSpace(s)
    if len(s)>512 {s=s[:512]}
    return s
}

// ParseDefenderCFAEventXML parses a bounded Windows Event Log XML record.
// Do not interpret System.Execution.ProcessID as the suspicious process:
// that PID often belongs to the Microsoft Defender event provider itself.
// Absence of a process field is reported as unknown, not guessed.
func ParseDefenderCFAEventXML(raw []byte)(DefenderCFAEvent,error){
    if len(raw)==0||len(raw)>64<<10{return DefenderCFAEvent{},errors.New("Defender event size invalid")}
    var x defenderXML
    if err:=xml.Unmarshal(raw,&x);err!=nil{return DefenderCFAEvent{},fmt.Errorf("Defender XML: %w",err)}
    if x.XMLName.Local!="Event" || x.System.Provider.Name!=defenderProvider ||
        x.System.Channel!=defenderChannel || x.System.RecordID==0 || cfaOutcome(x.System.EventID)==""{
        return DefenderCFAEvent{},errors.New("unexpected Defender event source or ID")
    }
    occurred,err:=time.Parse(time.RFC3339Nano,x.System.TimeCreated.SystemTime)
    if err!=nil{return DefenderCFAEvent{},fmt.Errorf("Defender event has no valid timestamp: %w",err)}
    result:=DefenderCFAEvent{RecordID:x.System.RecordID,EventID:x.System.EventID,
        Time:occurred.UTC(),Outcome:cfaOutcome(x.System.EventID)}
    for _,item:=range x.EventData.Data {
        key:=normalizeEventField(item.Name)
        value:=boundedEventValue(item.Value)
        if value==""{continue}
        switch key {
        case "processname","processpath","applicationname","applicationpath","imagepath","processimage":
            if result.ProcessPath=="" {result.ProcessPath=value}
        case "targetfilename","targetfilepath","targetpath","filepath","filename","path":
            if result.TargetPath=="" {result.TargetPath=value}
        case "processid","initiatingprocessid":
            // Explicit EventData only; often absent on CFA. Unknown stays zero.
            n,err:=strconv.ParseUint(value,0,32)
            if err==nil && n>0 {result.ProcessID=uint32(n)}
        }
    }
    return result,nil
}

// Correlation is deliberately contextual, never process attribution from
// filesystem scans. Only the official Defender event may name a process.
type Correlation struct {
    InWatchedFolder bool
    NearFileBurst bool
    Evidence string
    RecommendedAction string
}
func normalWindowsPath(path string)string{
    p:=strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path),"/","\\"))
    if len(p)<3 || p[1]!=':' || p[2]!='\\' {return ""}
    // Avoid claiming a match from malformed relative/traversal paths.
    for _,component:=range strings.Split(p[3:],"\\"){
        if component=="."||component==".."||component==""{return ""}
    }
    return strings.TrimRight(p,"\\")
}
func withinMonitoredRoot(path,root string)bool{
    p,r:=normalWindowsPath(path),normalWindowsPath(root)
    return p!=""&&r!=""&&(p==r||strings.HasPrefix(p,r+"\\"))
}
// CorrelateCFAEvent only reports that the *target reported by Defender*
// is within the selected directory, and optionally near a file burst in time.
// It does NOT claim Sentinel traced file modifications back to a PID.
func CorrelateCFAEvent(event DefenderCFAEvent,watchedRoot string,lastFileAlert *Alert)Correlation{
    match:=withinMonitoredRoot(event.TargetPath,watchedRoot)
    recent:=match && lastFileAlert!=nil && !lastFileAlert.Time.IsZero() &&
        absDuration(event.Time.Sub(lastFileAlert.Time))<=30*time.Second
    c:=Correlation{InWatchedFolder:match,NearFileBurst:recent}
    switch{
    case recent:c.Evidence="Alerte Defender dans le dossier surveillé, proche d'une rafale de fichiers ; causalité non établie"
    case match:c.Evidence="Cible Defender située dans le dossier surveillé ; origine indépendante de Sentinel"
    default:c.Evidence="Événement officiel Defender sans correspondance de dossier démontrée"
    }
    if event.Outcome=="blocked" {
        c.RecommendedAction="Écriture bloquée par Microsoft Defender ; examiner le programme dans Sécurité Windows, sans désactiver la protection"
    }else{
        c.RecommendedAction="Mode audit Defender : action possiblement autorisée ; vérifier les protections et le contexte avant toute décision"
    }
    return c
}
func absDuration(d time.Duration)time.Duration{if d<0{return -d};return d}
