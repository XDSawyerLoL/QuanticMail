package sentinel

import("testing";"time")
func TestProtectionAssessment(t *testing.T){
 now:=time.Now()
 for _,tc:=range []struct{raw,root,want string}{
 {`{"mode":1,"antivirus":true,"realtime":true,"running_mode":"Normal","default_folders":["C:\\Users\\Test\\Documents"],"extra_folders":[]}`,`C:\Users\Test\Documents\Work`,"configured_folder"},
 {`{"mode":1,"antivirus":true,"realtime":true,"running_mode":"Normal","default_folders":["C:\\Data"],"extra_folders":[]}`,`C:\Database`,"folder_unconfirmed"},
 {`{"mode":0,"antivirus":true,"realtime":true,"running_mode":"Normal"}`,"","disabled"},
 {`{"mode":2,"antivirus":true,"realtime":true,"running_mode":"Normal"}`,"","audit"},
 {`{"mode":3,"antivirus":true,"realtime":true,"running_mode":"Normal"}`,"","disk_only"},
 {`{"mode":1,"antivirus":true,"realtime":false,"running_mode":"Normal"}`,"","not_confirmed"},
 {`{"mode":1,"antivirus":true,"realtime":true,"running_mode":"Passive"}`,"","not_confirmed"},
 {`{"mode":9,"antivirus":true,"realtime":true,"running_mode":"Normal"}`,"","unknown"},
 }{
  s,err:=ParseProtectionSnapshot([]byte(tc.raw),now);if err!=nil{t.Fatal(err)}
  a:=AssessProtection(s,tc.root,now)
  if a.State!=tc.want{t.Fatalf("wanted %s got %+v",tc.want,a)}
  if AssessProtection(s,tc.root,now.Add(2*time.Minute)).State!="unknown"{t.Fatal("stale protection reported")}
 }
}
func TestProtectionReportRejectsMissingProviderFields(t *testing.T){
 for _,s:=range []string{`{}`,`{"mode":1,"antivirus":true}`,`{"mode":1,"antivirus":true,"realtime":true} {}`}{
  if _,err:=ParseProtectionSnapshot([]byte(s),time.Now());err==nil{t.Fatal("invalid report accepted")}
 }
}
