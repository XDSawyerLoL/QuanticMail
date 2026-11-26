package sentinel

import (
    "fmt"
    "strings"
    "testing"
    "time"
)

const defenderFixture = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Windows Defender"/>
<EventID>1123</EventID><EventRecordID>12345</EventRecordID>
<TimeCreated SystemTime="2026-11-24T06:32:10.1234567Z"/>
<Execution ProcessID="7777" ThreadID="9"/>
<Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
</System>
<EventData>
<Data Name="Process Name">C:\Apps\worker.exe</Data>
<Data Name="Path">C:\Users\Test\Documents\report.docx</Data>
</EventData>
</Event>`

func TestParseRealisticCFAEvent(t *testing.T){
    e,err:=ParseDefenderCFAEventXML([]byte(defenderFixture))
    if err!=nil {t.Fatal(err)}
    if e.RecordID!=12345||e.EventID!=1123||e.Outcome!="blocked"{
        t.Fatalf("wrong event metadata: %+v",e)
    }
    if e.ProcessPath!=`C:\Apps\worker.exe`||e.TargetPath!=`C:\Users\Test\Documents\report.docx`{
        t.Fatalf("Defender event fields lost: %+v",e)
    }
    if e.ProcessID!=0 {t.Fatal("misidentified System.Execution as responsible process")}
}
func TestDefenderOnlyAcceptsExplicitProcessID(t *testing.T){
    raw:=strings.Replace(defenderFixture,`<Data Name="Path">`,`<Data Name="ProcessId">4242</Data><Data Name="Path">`,1)
    e,err:=ParseDefenderCFAEventXML([]byte(raw))
    if err!=nil||e.ProcessID!=4242 {t.Fatalf("explicit PID lost %v %+v",err,e)}
}
func TestRejectSpoofedAndUnsupportedEvents(t *testing.T){
    for name,raw:=range map[string]string{
        "wrong provider":strings.Replace(defenderFixture,defenderProvider,"Random-Provider",1),
        "wrong channel":strings.Replace(defenderFixture,defenderChannel,"Application",1),
        "unsupported event":strings.Replace(defenderFixture,"<EventID>1123","<EventID>5007",1),
        "invalid record id":strings.Replace(defenderFixture,"<EventRecordID>12345","<EventRecordID>0",1),
        "invalid time":strings.Replace(defenderFixture,"2026-11-24T06:32:10.1234567Z","not-a-time",1),
        "invalid XML":`<Event><System>`,
        "oversized":strings.Repeat("a",65<<10),
    }{
        if _,err:=ParseDefenderCFAEventXML([]byte(raw));err==nil {t.Errorf("%s accepted",name)}
    }
}
func TestAllDefenderCFAOutcomes(t *testing.T){
    table:=map[int]string{1123:"blocked",1124:"audited",1127:"blocked",1128:"audited"}
    for id,expected:=range table{
        raw:=strings.Replace(defenderFixture,"<EventID>1123</EventID>",fmt.Sprintf("<EventID>%d</EventID>",id),1)
        e,err:=ParseDefenderCFAEventXML([]byte(raw))
        if err!=nil||e.Outcome!=expected {t.Errorf("event %d %v %+v",id,err,e)}
    }
}
func TestContextualCorrelationNeverGuessesCausation(t *testing.T){
    e,err:=ParseDefenderCFAEventXML([]byte(defenderFixture))
    if err!=nil{t.Fatal(err)}
    root:=`C:\Users\Test\Documents`
    burst:=&Alert{Time:e.Time.Add(4*time.Second),Rule:"Rafale de modifications"}
    c:=CorrelateCFAEvent(e,root,burst)
    if !c.InWatchedFolder||!c.NearFileBurst||!strings.Contains(c.Evidence,"causalité non établie"){
        t.Fatalf("missing bounded contextual correlation %+v",c)
    }
    c=CorrelateCFAEvent(e,`C:\Users\Test\DocumentsBackup`,burst)
    if c.InWatchedFolder||c.NearFileBurst{t.Fatal("directory prefix confusion")}
    c=CorrelateCFAEvent(e,root,&Alert{Time:e.Time.Add(-time.Minute)})
    if !c.InWatchedFolder||c.NearFileBurst{t.Fatal("out-of-window event was correlated")}
    e.TargetPath=""
    c=CorrelateCFAEvent(e,root,burst)
    if c.InWatchedFolder{t.Fatal("missing target falsely matches watched directory")}
}
func TestWindowsPathValidationForCorrelation(t *testing.T){
    root:=`C:\Users\Test\Documents`
    for _,path:=range []string{
        `C:\Users\Test\DocumentsX\a.txt`,
        `C:\Users\Test\Documents\..\Elsewhere\a.txt`,
        `C:relative\a.txt`,
        `\\server\share\file.txt`,
    }{
        if withinMonitoredRoot(path,root){t.Errorf("unsafe path matched root: %q",path)}
    }
    if !withinMonitoredRoot(`c:/users/test/documents/approved.txt`,root){t.Fatal("case insensitive Windows path should match")}
}
