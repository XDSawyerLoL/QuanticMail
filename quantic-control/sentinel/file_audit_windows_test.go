//go:build windows

package sentinel

import "testing"

// CI may lack permission to read the Security channel; that's explicitly a
// skipped live-source test, not proof of process attribution in that runner.
func TestNativeSecurityFileAuditWithoutModification(t *testing.T){
 events,overflow,err:=ReadRecentFileAudits(8)
 if err!=nil{t.Skipf("Windows Security 4663 unavailable (expected on unprivileged clients): %v",err)}
 if len(events)>8{t.Fatal("unbounded query")}
 for _,e:=range events{
  if e.RecordID==0||e.AccessMask&writeCapableMask==0{
   t.Fatalf("unexpected Security file audit: %+v",e)
  }
 }
 if overflow{t.Log("Security 4663 data exceeded 8 recent records")}
}
