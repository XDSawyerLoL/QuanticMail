//go:build windows

package main

import(
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "syscall"
 "time"
 "unsafe"

 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

const backupHealthInterval=2*time.Second

// An installation-specific, process-owned event. It is advisory telemetry,
// not an authenticated IPC channel or protection from same-user tampering.
// No status file can remain stale after ordinary process termination.
func backupHealthEventName(m installManifest)(string,error){
 raw,err:=json.Marshal(m)
 if err!=nil{return "",err}
 digest:=sha256.Sum256(raw)
 return "Local\\QuanticSentinelBackupHealthV2-"+hex.EncodeToString(digest[:]),nil
}
func newBackupHealthEvent(m installManifest)(uintptr,error){
 name,err:=backupHealthEventName(m);if err!=nil{return 0,err}
 h,_,callErr:=createNamedEvent.Call(0,1,0,uintptr(unsafe.Pointer(u16(name))))
 if h==0{return 0,fmt.Errorf("backup status event unavailable: %v",callErr)}
 if callErr==errorAlreadyExists{closeWinHandle.Call(h);return 0,errors.New("backup status event collision")}
 return h,nil
}
func checkHeldBackups(locks []*sentinel.BackupLock,requested int)bool{
 if requested<1||requested!=len(locks){return false}
 for _,l:=range locks{if l==nil||!l.Healthy(){return false}}
 return true
}
func setBackupHealth(h uintptr,healthy bool){
 if healthy{setNamedEvent.Call(h)}else{residentKernel.NewProc("ResetEvent").Call(h)}
}
func monitorBackupHealth(ctx context.Context,h uintptr,locks []*sentinel.BackupLock,requested int,done chan<- struct{}){
 defer close(done)
 defer setBackupHealth(h,false)
 tick:=time.NewTicker(backupHealthInterval)
 defer tick.Stop()
 for{
  if ctx.Err()!=nil{return}
  setBackupHealth(h,checkHeldBackups(locks,requested))
  select{
  case <-ctx.Done():return
  case <-tick.C:
  }
 }
}
type backupHealthState string
const(
 backupStatusAbsent backupHealthState="absent"
 backupStatusUnconfirmed backupHealthState="unconfirmed"
 backupStatusHeld backupHealthState="held"
 backupStatusUnknown backupHealthState="unknown"
)
func readResidentBackupState(m installManifest)backupHealthState{
 name,err:=backupHealthEventName(m)
 if err!=nil{return backupStatusUnknown}
 // GUI never acquires EVENT_MODIFY_STATE; it observes the event only and
 // immediately closes its handle so it cannot keep a dead agent's event alive.
 h,_,callErr:=openNamedEvent.Call(synchronize,0,uintptr(unsafe.Pointer(u16(name))))
 if h==0{
  if callErr==syscall.ERROR_FILE_NOT_FOUND{return backupStatusAbsent}
  return backupStatusUnknown
 }
 defer closeWinHandle.Call(h)
 result,_,_:=waitWinObject.Call(h,0)
 switch result{
 case 0:if len(m.Backups)>0{return backupStatusHeld};return backupStatusUnknown
 case 258:return backupStatusUnconfirmed
 default:return backupStatusUnknown
 }
}
