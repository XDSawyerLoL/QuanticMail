//go:build windows

package sentinel

import (
    "errors"
    "fmt"
    "runtime"
    "syscall"
    "unicode/utf16"
    "unsafe"
)

const (
    evtQueryChannelPath = 0x1
    evtQueryReverseDirection = 0x200
    evtRenderEventXML = 1
    defenderEventXMLMaxBytes = 64 << 10
)
var (
    winevt = syscall.NewLazyDLL("wevtapi.dll")
    evtQuery = winevt.NewProc("EvtQuery")
    evtNext = winevt.NewProc("EvtNext")
    evtRender = winevt.NewProc("EvtRender")
    evtClose = winevt.NewProc("EvtClose")
)

func eventSyscallError(err error, operation string)error{
    if err!=nil && err!=syscall.Errno(0){return fmt.Errorf("%s: %w",operation,err)}
    return fmt.Errorf("%s failed",operation)
}

// ReadRecentCFA queries the LOCAL Windows Defender Operational event channel
// using Windows Event Log APIs. No PowerShell, no subprocess, no registry
// editing and no elevation request. Query is strictly restricted to CFA IDs.
// The 65th returned event is an overflow signal, not silently discarded.
func ReadRecentCFA(limit int)([]DefenderCFAEvent,bool,error){
    if limit<1 || limit>64{return nil,false,errors.New("Defender query limit must be 1..64")}
    path,err:=syscall.UTF16PtrFromString(defenderChannel)
    if err!=nil{return nil,false,err}
    expression,err:=syscall.UTF16PtrFromString("*[System[(EventID=1123 or EventID=1124 or EventID=1127 or EventID=1128)]]")
    if err!=nil{return nil,false,err}
    result,_,callErr:=evtQuery.Call(0,
        uintptr(unsafe.Pointer(path)),uintptr(unsafe.Pointer(expression)),
        evtQueryChannelPath|evtQueryReverseDirection)
    runtime.KeepAlive(path);runtime.KeepAlive(expression)
    if result==0{return nil,false,eventSyscallError(callErr,"EvtQuery Defender")}
    defer evtClose.Call(result)
    events:=make([]DefenderCFAEvent,0,limit)
    for index:=0;index<=limit;index++{
        var eventHandle uintptr
        var returned uint32
        ok,_,nextErr:=evtNext.Call(result,1,uintptr(unsafe.Pointer(&eventHandle)),0,0,
            uintptr(unsafe.Pointer(&returned)))
        if ok==0{
            if nextErr==syscall.Errno(259) {break} // ERROR_NO_MORE_ITEMS
            return nil,false,eventSyscallError(nextErr,"EvtNext Defender")
        }
        if returned!=1||eventHandle==0{return nil,false,errors.New("Defender returned invalid handle count")}
        if index==limit{
            evtClose.Call(eventHandle)
            return events,true,nil
        }
        raw,renderErr:=renderDefenderEvent(eventHandle)
        evtClose.Call(eventHandle)
        if renderErr!=nil{return nil,false,renderErr}
        parsed,parseErr:=ParseDefenderCFAEventXML(raw)
        if parseErr!=nil{return nil,false,parseErr}
        events=append(events,parsed)
    }
    return events,false,nil
}

func renderDefenderEvent(event uintptr)([]byte,error){
    var used,propertyCount uint32
    ok,_,firstErr:=evtRender.Call(0,event,evtRenderEventXML,0,0,
        uintptr(unsafe.Pointer(&used)),uintptr(unsafe.Pointer(&propertyCount)))
    if ok!=0 {return nil,errors.New("EvtRender unexpectedly returned empty success")}
    if firstErr!=syscall.Errno(122) {return nil,eventSyscallError(firstErr,"EvtRender length")}
    if used<4 || used>defenderEventXMLMaxBytes || used%2!=0{
        return nil,errors.New("Defender event XML size exceeds strict limit")
    }
    buf:=make([]uint16,used/2)
    ok,_,renderErr:=evtRender.Call(0,event,evtRenderEventXML,uintptr(used),
        uintptr(unsafe.Pointer(&buf[0])),uintptr(unsafe.Pointer(&used)),
        uintptr(unsafe.Pointer(&propertyCount)))
    runtime.KeepAlive(buf)
    if ok==0 {return nil,eventSyscallError(renderErr,"EvtRender XML")}
    if used<4||used>uint32(len(buf)*2)||used%2!=0{return nil,errors.New("invalid Defender XML length")}
    chars:=buf[:used/2]
    if chars[len(chars)-1]==0{chars=chars[:len(chars)-1]}
    // Convert UTF-16 returned by EvtRender to UTF-8 for encoding/xml.
    text:=string(utf16.Decode(chars))
    if len(text)>defenderEventXMLMaxBytes{return nil,errors.New("Defender XML too long")}
    return []byte(text),nil
}
