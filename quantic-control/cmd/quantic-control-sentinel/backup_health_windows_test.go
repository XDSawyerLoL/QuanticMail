//go:build windows

package main

import(
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

func TestBackupHealthTracksHeldHandleAndRelease(t *testing.T){
 path:=filepath.Join(t.TempDir(),"fixture.bak")
 if err:=os.WriteFile(path,[]byte("fixture"),0600);err!=nil{t.Fatal(err)}
 lock,err:=sentinel.LockBackup(path);if err!=nil{t.Fatal(err)}
 defer lock.Close()
 m:=installManifest{Version:residentVersion,ExeHash:strings.Repeat("a",64),Root:filepath.Dir(path),Backups:[]sentinel.BackupIdentity{lock.Identity()}}
 h,err:=newBackupHealthEvent(m);if err!=nil{t.Fatal(err)}
 defer func(){if h!=0{closeWinHandle.Call(h)}}()
 if state:=readResidentBackupState(m);state!=backupStatusUnconfirmed{t.Fatalf("initial status: %s",state)}
 if collision,e:=newBackupHealthEvent(m);e==nil{closeWinHandle.Call(collision);t.Fatal("event collision accepted")}
 ctx,cancel:=context.WithCancel(context.Background())
 done:=make(chan struct{})
 name,err:=backupHealthEventName(m);if err!=nil{t.Fatal(err)}
 go monitorBackupHealth(ctx,&healthPublisher{event:h,name:name},[]*sentinel.BackupLock{lock},1,done)
 defer func(){cancel();<-done}()
 await:=func(want backupHealthState){
  t.Helper()
  for until:=time.Now().Add(5*time.Second);time.Now().Before(until);time.Sleep(25*time.Millisecond){
   if readResidentBackupState(m)==want{return}
  }
  t.Fatalf("wanted %s, got %s",want,readResidentBackupState(m))
 }
 await(backupStatusHeld)
 if err:=lock.Close();err!=nil{t.Fatal(err)}
 await(backupStatusUnconfirmed)
 cancel()
 <-done
 closeWinHandle.Call(h);h=0
 await(backupStatusAbsent)
}


// An expired pulse can still be signalled and held open by a frozen agent.
// Test the actual Windows event lookup, with deterministic bucket selection.
func TestFrozenBackupAgentSignalExpires(t *testing.T){
 m:=installManifest{Version:residentVersion,ExeHash:strings.Repeat("b",64),Root:t.TempDir()}
 h,err:=newBackupHealthEvent(m);if err!=nil{t.Fatal(err)}
 defer closeWinHandle.Call(h)
 name,err:=backupHealthEventName(m);if err!=nil{t.Fatal(err)}
 p:=&healthPublisher{event:h,name:name}
 defer p.clear()
 p.publish(true)
 if p.pulse==0{t.Fatal("health pulse not published")}
 if !hasFreshHealthPulse(name,p.bucket)||!hasFreshHealthPulse(name,p.bucket+1){t.Fatal("fresh pulse refused")}
 if hasFreshHealthPulse(name,p.bucket+2){t.Fatal("stale positive pulse accepted")}
 // Even with the long-lived status event still signalled, the old
 // pulse is excluded by the bounded freshness window.
 state,_,_:=waitWinObject.Call(h,0)
 if state!=0{t.Fatal("test did not retain stale positive signal")}
 p.clear()
 if hasFreshHealthPulse(name,p.bucket){t.Fatal("closed pulse still appears active")}
}
