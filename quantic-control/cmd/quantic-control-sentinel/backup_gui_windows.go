//go:build windows

package main

import(
 "path/filepath"
 "fmt"
 "strings"
 "runtime"
 "syscall"
 "unicode/utf16"
 "unsafe"

 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

type backupOpenFileName struct{
 size uint32
 owner,instance uintptr
 filter,customFilter *uint16
 maxCustomFilter,filterIndex uint32
 file *uint16
 maxFile uint32
 fileTitle *uint16
 maxFileTitle uint32
 initialDir,title *uint16
 flags uint32
 fileOffset,fileExtension uint16
 defaultExt *uint16
 customData,hook uintptr
 templateName *uint16
 reserved uintptr
 reservedDWORD,flagsEx uint32
}

var backupHandles []*sentinel.BackupLock
var backupButton,backupLabel uintptr

func chooseBackup(owner uintptr)(string,bool){
 filter:=utf16.Encode([]rune("Copies de sauvegarde (*.bak;*.backup;*.zip;*.7z;*.qvb)\x00*.bak;*.backup;*.zip;*.7z;*.qvb\x00\x00"))
 buf:=make([]uint16,32768)
 title:=u16("Sélectionner une copie de sauvegarde inactive")
 dialog:=backupOpenFileName{size:uint32(unsafe.Sizeof(backupOpenFileName{})),
  owner:owner,filter:&filter[0],filterIndex:1,file:&buf[0],maxFile:uint32(len(buf)),title:title,
  flags:0x00080000|0x00001000|0x00000800|0x00000008|0x00100000}
 ok,_,_:=syscall.NewLazyDLL("comdlg32.dll").NewProc("GetOpenFileNameW").Call(uintptr(unsafe.Pointer(&dialog)))
 runtime.KeepAlive(filter);runtime.KeepAlive(buf);runtime.KeepAlive(title);runtime.KeepAlive(&dialog)
 if ok==0{return "",false}
 path:=syscall.UTF16ToString(buf)
 return path,path!=""
}
func selectedBackupIdentities()[]sentinel.BackupIdentity{
 out:=make([]sentinel.BackupIdentity,0,len(backupHandles))
 for _,l:=range backupHandles{out=append(out,l.Identity())}
 return out
}
var lastResidentBackupState backupHealthState
var previouslyHeld bool
func refreshBackupLabel(){
 healthy:=0
 for _,l:=range backupHandles{if l.Healthy(){healthy++}}
 detail:="Agent : non configuré."
 state:=backupStatusUnknown
 if m,e:=readManifest();e==nil{
  state=readResidentBackupState(m)
  switch state{
  case backupStatusHeld:detail=fmt.Sprintf("Agent : %d/%d verrous signalés actifs.",len(m.Backups),len(m.Backups))
  case backupStatusAbsent:detail="Agent : état absent (arrêté ou ancienne version)."
  case backupStatusUnconfirmed:
   if len(m.Backups)==0{detail="Agent : aucune sauvegarde configurée."}else{detail="Agent : protection non confirmée."}
  default:detail="Agent : état inconnu."
  }
  if previouslyHeld&&lastResidentBackupState==backupStatusHeld&&state!=backupStatusHeld{
   addLog("ATTENTION : verrous résidents non confirmés. Vérifiez l'agent avant de compter sur la protection.")
  }
 }
 if state==backupStatusHeld{previouslyHeld=true}
 lastResidentBackupState=state
 setLabel(backupLabel,fmt.Sprintf("Copies verrouillées ici : %d/%d. %s",healthy,len(backupHandles),detail))
}
func releaseBackup(hwnd uintptr){
 remaining:=make([]*sentinel.BackupLock,0)
 for _,l:=range backupHandles{if err:=l.Close();err!=nil{remaining=append(remaining,l)}}
 backupHandles=remaining
 refreshBackupLabel()
 if len(remaining)>0{messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Certains verrous locaux n'ont pas pu être libérés."))),uintptr(unsafe.Pointer(u16("Sauvegardes"))),0x30)}
}
func toggleBackup(hwnd uintptr){
 if len(backupHandles)>=sentinel.MaxBackupLocks{
  messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Limite de 16 copies atteinte."))),uintptr(unsafe.Pointer(u16("Sauvegardes"))),0x30)
  return
 }
 path,ok:=chooseBackup(hwnd)
 if !ok{return}
 msg:="Protéger cette copie inactive ?\n\n"+path+"\n\nLes écritures et suppressions seront refusées tant qu'un verrou est détenu. Installez l'agent après avoir sélectionné toutes les copies pour les reprendre en arrière-plan. Pour modifier sa sélection, désinstallez puis réinstallez l'agent."
 decision,_,_:=messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16(msg))),uintptr(unsafe.Pointer(u16("Protection temporaire d'une copie"))),0x134)
 if decision!=6{return}
 lock,err:=sentinel.LockBackup(path)
 if err!=nil{
  messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Protection non activée : "+err.Error()))),uintptr(unsafe.Pointer(u16("Copie de sauvegarde"))),0x30)
  return
 }
 for _,old:=range backupHandles{if strings.EqualFold(old.Path(),lock.Path()){_ =lock.Close();return}}
 backupHandles=append(backupHandles,lock)
 refreshBackupLabel()
 addLog("Copie verrouillée en lecture seule : "+filepath.Base(path))
}
