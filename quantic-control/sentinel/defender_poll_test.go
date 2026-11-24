package sentinel

import (
    "context"
    "errors"
    "sync/atomic"
    "testing"
    "time"
)

func TestDefenderPollDeduplicatesAndIgnoresHistoricEvents(t *testing.T){
    start:=time.Now().Add(-time.Second)
    recent:=DefenderCFAEvent{RecordID:5,EventID:1123,Time:time.Now(),Outcome:"blocked"}
    historic:=DefenderCFAEvent{RecordID:4,EventID:1123,Time:start.Add(-time.Hour),Outcome:"blocked"}
    var calls atomic.Int32
    read:=func(limit int)([]DefenderCFAEvent,bool,error){
        calls.Add(1)
        if limit!=64 {t.Error("unbounded reader")}
        return []DefenderCFAEvent{recent,historic},false,nil
    }
    ctx,cancel:=context.WithTimeout(context.Background(),200*time.Millisecond)
    defer cancel()
    out:=make(chan DefenderNotice,10)
    done:=make(chan struct{})
    go func(){MonitorDefenderEvents(ctx,start,15*time.Millisecond,read,out);close(done)}()
    <-done
    count:=0
    close(out)
    for notice:=range out{
        if notice.Event!=nil {count++;if notice.Event.RecordID!=5{t.Fatal("historic event emitted")}}
    }
    if calls.Load()<3||count!=1{t.Fatalf("polls %d, notifications %d",calls.Load(),count)}
}
func TestDefenderPollMarksLossAndRecovery(t *testing.T){
    start:=time.Now().Add(-time.Second)
    var calls atomic.Int32
    read:=func(int)([]DefenderCFAEvent,bool,error){
        if calls.Add(1)==1 {return nil,false,errors.New("access denied")}
        return []DefenderCFAEvent{{RecordID:9,Time:time.Now(),EventID:1124,Outcome:"audited"}},true,nil
    }
    ctx,cancel:=context.WithTimeout(context.Background(),90*time.Millisecond)
    defer cancel()
    out:=make(chan DefenderNotice,128)
    MonitorDefenderEvents(ctx,start,15*time.Millisecond,read,out)
    if calls.Load()<2{t.Fatalf("missing recovery poll: %d",calls.Load())}
    close(out)
    failures,recovery,overflow,events:=0,0,0,0
    for notice:=range out{
        if notice.Err!=nil{failures++}
        if notice.Restored{recovery++}
        if notice.Overflow{overflow++}
        if notice.Event!=nil{events++}
    }
    if failures!=1||recovery!=1||overflow==0||events==0 {
        t.Fatalf("failures=%d recovery=%d overflow=%d events=%d",failures,recovery,overflow,events)
    }
}
func TestDefenderPollNoUnrequestedReaderAfterCancellation(t *testing.T){
    ctx,cancel:=context.WithCancel(context.Background())
    cancel()
    calls:=0
    read:=func(int)([]DefenderCFAEvent,bool,error){calls++;return nil,false,nil}
    out:=make(chan DefenderNotice)
    // An already canceled context may still race against a one-time
    // non-blocking query; no second query or blocked send is permitted.
    finished:=make(chan struct{})
    go func(){MonitorDefenderEvents(ctx,time.Now(),time.Millisecond,read,out);close(finished)}()
    select{case <-finished:case <-time.After(time.Second):t.Fatal("monitor did not stop")}
    if calls>1{t.Fatal("excessive reads after cancellation")}
}
