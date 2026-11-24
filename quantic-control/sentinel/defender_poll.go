package sentinel

import (
    "context"
    "errors"
    "fmt"
    "sort"
    "time"
)

type CFAReader func(limit int)([]DefenderCFAEvent,bool,error)

type DefenderNotice struct{
    Event *DefenderCFAEvent
    Err error
    Overflow bool
}

// MonitorDefenderEvents is a read-only, bounded event-log poller. It never
// changes Defender settings, attributes a filesystem event to a process, or
// executes responses. Failures remain visible instead of silently implying
// monitoring coverage. At startup it ignores historical events.
func MonitorDefenderEvents(ctx context.Context,started time.Time,period time.Duration,
    read CFAReader,out chan<- DefenderNotice){
    if read==nil||out==nil||ctx==nil{return}
    if period<=0{period=10*time.Second}
    ticker:=time.NewTicker(period)
    defer ticker.Stop()
    seen:=make(map[string]bool,512)
    hadError:=false
    send:=func(item DefenderNotice)bool{
        select{case out<-item:return true;case <-ctx.Done():return false}
    }
    poll:=func()bool{
        events,overflow,err:=read(64)
        if err!=nil{
            if !hadError && !send(DefenderNotice{Err:fmt.Errorf("Defender CFA journal unreadable: %w",err)}){return false}
            hadError=true
            return true
        }
        if hadError{
            if !send(DefenderNotice{Err:errors.New("Defender CFA journal access restored")}){return false}
            hadError=false
        }
        if overflow && !send(DefenderNotice{Overflow:true}){return false}
        // EvtQuery returns reverse chronological order. Normalize for a
        // deterministic persisted history and the burst correlation window.
        sort.Slice(events,func(i,j int)bool{
            if events[i].Time.Equal(events[j].Time){return events[i].RecordID<events[j].RecordID}
            return events[i].Time.Before(events[j].Time)
        })
        for _,e:=range events{
            if e.Time.Before(started) || e.Time.After(time.Now().Add(5*time.Second)){continue}
            key:=fmt.Sprintf("%d:%d",e.RecordID,e.Time.UnixNano())
            if seen[key]{continue}
            seen[key]=true
            if !send(DefenderNotice{Event:&e}){return false}
        }
        if len(seen)>512 {
            // Deduplication remains bounded, and recent records repeat in
            // snapshots; retaining only the latest batch avoids memory growth.
            seen=make(map[string]bool,512)
            for _,e:=range events{seen[fmt.Sprintf("%d:%d",e.RecordID,e.Time.UnixNano())]=true}
        }
        return true
    }
    if !poll(){return}
    for{
        select{
        case <-ctx.Done():return
        case <-ticker.C:if !poll(){return}
        }
    }
}
