package sentinel

import(
 "errors"
 "strings"
 "testing"
)

const audit4663Fixture = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4663</EventID><EventRecordID>71</EventRecordID>
<TimeCreated SystemTime="2026-11-24T08:00:00.0000000Z"/>
<Execution ProcessID="9999"/>
<Channel>Security</Channel></System>
<EventData>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Users\Test\Documents\report.docx</Data>
<Data Name="ProcessId">0x4d2</Data>
<Data Name="ProcessName">C:\Apps\editor.exe</Data>
<Data Name="AccessMask">0x2</Data>
</EventData></Event>`

func TestSecurity4663HasRealProcessAndFile(t *testing.T){
 e,err:=ParseSecurity4663XML([]byte(audit4663Fixture))
 if err!=nil{t.Fatal(err)}
 if e.ProcessID!=1234||e.ProcessName!=`C:\Apps\editor.exe`||e.ObjectName!=`C:\Users\Test\Documents\report.docx`||e.AccessMask!=2{
  t.Fatalf("incorrect attribution: %+v",e)
 }
 if e.ProcessID==9999{t.Fatal("used provider PID from System.Execution")}
 if !FileAuditCorrelation(e,`C:\Users\Test\Documents`){t.Fatal("file not recognized as within watched folder")}
 if FileAuditCorrelation(e,`C:\Users\Test\DocumentsOther`){t.Fatal("prefix confusion")}
}
func TestSecurity4663RejectsWrongProviderOrNonWrite(t *testing.T){
 cases:=map[string]string{
  "not file":strings.Replace(audit4663Fixture,"<Data Name=\"ObjectType\">File</Data>","<Data Name=\"ObjectType\">Key</Data>",1),
  "read only":strings.Replace(audit4663Fixture,"<Data Name=\"AccessMask\">0x2</Data>","<Data Name=\"AccessMask\">0x1</Data>",1),
  "wrong event ID":strings.Replace(audit4663Fixture,"<EventID>4663</EventID>","<EventID>4656</EventID>",1),
  "wrong provider":strings.Replace(audit4663Fixture,securityProvider,"Unexpected-Provider",1),
  "wrong channel":strings.Replace(audit4663Fixture,"<Channel>Security</Channel>","<Channel>Application</Channel>",1),
  "relative file":strings.Replace(audit4663Fixture,`C:\Users\Test\Documents\report.docx`,"..\\report.docx",1),
  "bad mask":strings.Replace(audit4663Fixture,"<Data Name=\"AccessMask\">0x2</Data>","<Data Name=\"AccessMask\">notanumber</Data>",1),
 }
 for name,fixture:=range cases{
  if _,err:=ParseSecurity4663XML([]byte(fixture));!errors.Is(err,ErrNotWriteFileAudit){
   t.Errorf("%s accepted unexpectedly: %v",name,err)
  }
 }
}
func TestSecurity4663MissingExplicitPIDDoesNotGuess(t *testing.T){
 raw:=strings.Replace(audit4663Fixture,"<Data Name=\"ProcessId\">0x4d2</Data>","",1)
 e,err:=ParseSecurity4663XML([]byte(raw))
 if err!=nil{t.Fatal(err)}
 if e.ProcessID!=0{t.Fatal("invented a PID from provider field")}
}
func TestSecurity4663UnsupportedDataIsBounded(t *testing.T){
 raw:=strings.Replace(audit4663Fixture,`C:\Apps\editor.exe`,strings.Repeat("P",600),1)
 e,err:=ParseSecurity4663XML([]byte(raw))
 if err!=nil{t.Fatal(err)}
 if len(e.ProcessName)>512{t.Fatal("process path exceeded audit field budget")}
 if _,err:=ParseSecurity4663XML([]byte(strings.Repeat("A",65000)));err==nil{t.Fatal("huge XML accepted")}
}
