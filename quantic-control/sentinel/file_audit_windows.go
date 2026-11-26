//go:build windows

package sentinel

import(
 "errors"
 "runtime"
 "syscall"
 "unsafe"
)

// ReadRecentFileAudits queries the local Windows Security 4663 event channel
// without enabling system-wide auditing or changing folder permissions.
// Access can be denied on ordinary user accounts; this is surfaced as an
// explicit degraded state. Only read/write-capable File audits are returned.
func ReadRecentFileAudits(limit int)([]FileAccessAudit,bool,error){
 if limit<1||limit>64{return nil,false,errors.New("Security 4663 query limit must be 1..64")}
 path,err:=syscall.UTF16PtrFromString(securityChannel)
 if err!=nil{return nil,false,err}
 xpath,err:=syscall.UTF16PtrFromString("*[System[(EventID=4663)]]")
 if err!=nil{return nil,false,err}
 query,_,callErr:=evtQuery.Call(0,uintptr(unsafe.Pointer(path)),
  uintptr(unsafe.Pointer(xpath)),evtQueryChannelPath|evtQueryReverseDirection)
 runtime.KeepAlive(path);runtime.KeepAlive(xpath)
 if query==0{return nil,false,eventSyscallError(callErr,"EvtQuery Security 4663")}
 defer evtClose.Call(query)
 records:=make([]FileAccessAudit,0,limit)
 // Count at most limit+1 source records, even if many are irrelevant.
 // Returning an overflow flag is essential: high-volume Security logs can
 // omit relevant records in the most recent page.
 for i:=0;i<=limit;i++{
  var handle uintptr
  var returned uint32
  ok,_,nextErr:=evtNext.Call(query,1,uintptr(unsafe.Pointer(&handle)),0,0,
   uintptr(unsafe.Pointer(&returned)))
  if ok==0{
   if nextErr==syscall.Errno(259){break}
   return nil,false,eventSyscallError(nextErr,"EvtNext Security")
  }
  if handle==0||returned!=1{return nil,false,errors.New("invalid Security 4663 event handle")}
  if i==limit{evtClose.Call(handle);return records,true,nil}
  raw,renderErr:=renderDefenderEvent(handle)
  evtClose.Call(handle)
  if renderErr!=nil{return nil,false,renderErr}
  record,parseErr:=ParseSecurity4663XML(raw)
  if errors.Is(parseErr,ErrNotWriteFileAudit){continue}
  if parseErr!=nil{return nil,false,parseErr}
  records=append(records,record)
 }
 return records,false,nil
}
