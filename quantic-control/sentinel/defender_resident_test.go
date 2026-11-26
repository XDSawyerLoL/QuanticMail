package sentinel

import (
    "context"
    "os"
    "path/filepath"
    "strings"
    "sync/atomic"
    "testing"
    "time"
)

func TestResidentPersistsAuthenticSourceFieldsAndAdvice(t *testing.T){
    dir:=t.TempDir()
    watched:=filepath.Join(dir,"observed")
    if err:=os.Mkdir(watched,0700);err!=nil{t.Fatal(err)}
    log:=filepath.Join(dir,"events.jsonl")
    ctx,cancel:=context.WithCancel(context.Background())
    var calls atomic.Int32
    reader:=func(limit int)([]DefenderCFAEvent,bool,error){
        calls.Add(1)
        return []DefenderCFAEvent{{
            RecordID:998,EventID:1123,Time:time.Now().UTC(),
            Outcome:"blocked",ProcessPath:`C:\Apps\reported.exe`,
            TargetPath:`C:\Users\Test\Documents\file.txt`,
        }},false,nil
    }
    done:=make(chan error,1)
    go func(){done<-runResidentWithDefender(ctx,watched,log,reader,true)}()
    time.Sleep(400*time.Millisecond)
    cancel()
    select{case err:=<-done:if err!=nil{t.Fatal(err)};case <-time.After(4*time.Second):t.Fatal("agent did not stop")}
    if calls.Load()==0{t.Fatal("Defender event source not consulted")}
    records,err:=RecentRecords(log,30)
    if err!=nil{t.Fatal(err)}
    found:=false
    for _,r:=range records {
        if r.Type!="defender_cfa"{continue}
        found=true
        if r.Defender==nil||r.Defender.ProcessPath!=`C:\Apps\reported.exe`||
            r.Defender.EventID!=1123||!strings.Contains(r.Advice,"Microsoft Defender"){
            t.Fatalf("incomplete local evidence: %+v",r)
        }
        if strings.Contains(strings.ToLower(r.Evidence),"preuve de causalité"){t.Fatal("causality overstated")}
    }
    if !found{t.Fatalf("Defender evidence not recorded: %+v",records)}
}
