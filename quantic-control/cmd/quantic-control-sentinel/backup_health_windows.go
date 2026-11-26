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
 "runtime"
 "time"
 "unsafe"

 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

const backupHealthInterval=2*time.Second
const backupHealthBucketMS=4000

// An installation-specific, process-owned event. It is advisory telemetry,
// not an authenticated IPC channel or protection from same-user tampering.
// No status file can remain stale after ordinary process termination.
func backupHealthEventName(m installManifest)(string,error){
 raw,err:=json.Marshal(m)
 if err!=nil{return "",err}
 digest:=sha256.Sum256(raw)
 return "Local\\QuanticSentinelBackupHealthV3-"+hex.EncodeToString(digest[:]),nil
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
// Freshness is measured with Windows system uptime, not wall-clock time.
// A held event from an unresponsive agent is insufficient after its bucket
// expires. The x64 build is the supported architecture.
func currentHealthBucket()(uint64,bool){
 if runtime.GOARCH!="amd64"&&runtime.GOARCH!="arm64"{return 0,false}
 ticks,_,_:=residentKernel.NewProc("GetTickCount64").Call()
 return uint64(ticks)/backupHealthBucketMS,true
}
func healthPulseName(name string,bucket uint64)string{
 return fmt.Sprintf("%s-pulse-%016x",name,bucket)
}
type healthPublisher struct{
 event uintptr
 name string
 pulse uintptr
 bucket uint64
}
func(p *healthPublisher) clear(){
 setBackupHealth(p.event,false)
 if p.pulse!=0{closeWinHandle.Call(p.pulse);p.pulse=0}
}
func(p *healthPublisher) publish(healthy bool){
 bucket,ok:=currentHealthBucket()
 if !healthy||!ok{p.clear();return}
 if p.pulse!=0&&p.bucket==bucket{setBackupHealth(p.event,true);return}
 // A pulse is initially signalled and exists only while its owner holds it.
 name:=healthPulseName(p.name,bucket)
 h,_,err:=createNamedEvent.Call(0,1,1,uintptr(unsafe.Pointer(u16(name))))
 if h==0||err==errorAlreadyExists{
  if h!=0{closeWinHandle.Call(h)}
  p.clear();return
 }
 old:=p.pulse
 p.pulse=h;p.bucket=bucket
 if old!=0{closeWinHandle.Call(old)}
 setBackupHealth(p.event,true)
}
func monitorBackupHealth(ctx context.Context,p *healthPublisher,locks []*sentinel.BackupLock,requested int,done chan<- struct{}){
 defer close(done)
 defer p.clear()
 tick:=time.NewTicker(backupHealthInterval)
 defer tick.Stop()
 for{
  if ctx.Err()!=nil{return}
  p.publish(checkHeldBackups(locks,requested))
  select{
  case <-ctx.Done():return
  case <-tick.C:
  }
 }
}
func hasFreshHealthPulse(name string,bucket uint64)bool{
 for i:=uint64(0);i<2&&i<=bucket;i++{
  h,_,_:=openNamedEvent.Call(synchronize,0,uintptr(unsafe.Pointer(u16(healthPulseName(name,bucket-i)))))
  if h==0{continue}
  result,_,_:=waitWinObject.Call(h,0)
  closeWinHandle.Call(h)
  if result==0{return true}
 }
 return false
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
 case 0:
  bucket,ok:=currentHealthBucket()
  if len(m.Backups)>0&&ok&&hasFreshHealthPulse(name,bucket){return backupStatusHeld}
  return backupStatusUnconfirmed
 case 258:return backupStatusUnconfirmed
 default:return backupStatusUnknown
 }
}
