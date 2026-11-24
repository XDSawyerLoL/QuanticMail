//go:build windows

package sentinel

import "testing"

// CI smoke: check that native Windows EvtQuery calls do not crash. A runner
// without Microsoft Defender Operational channel cannot prove live event
// integration and is reported as skipped, not fabricated evidence.
func TestReadNativeDefenderEventLogWithoutModification(t *testing.T){
    events,overflow,err:=ReadRecentCFA(8)
    if err!=nil{
        t.Skipf("native Defender Operational channel unavailable: %v",err)
    }
    if len(events)>8{t.Fatal("unbounded Defender event query")}
    if overflow{t.Log("Defender channel contained more than 8 CFA events; query is truncated")}
    for _,e:=range events{
        if e.RecordID==0||cfaOutcome(e.EventID)==""{
            t.Fatalf("unexpected event from channel: %+v",e)
        }
    }
}
