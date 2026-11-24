//go:build windows

package main

import(
 "path/filepath"
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

var backupHandle *sentinel.BackupLock
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
func releaseBackup(hwnd uintptr)bool{
 if backupHandle==nil{return true}
 if err:=backupHandle.Close();err!=nil{
  messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Libération impossible : "+err.Error()))),uintptr(unsafe.Pointer(u16("Copie de sauvegarde"))),0x30)
  return false
 }
 backupHandle=nil
 setLabel(backupButton,"Verrouiller une copie")
 setLabel(backupLabel,"Copie de sauvegarde : aucun verrou actif.")
 return true
}
func toggleBackup(hwnd uintptr){
 if backupHandle!=nil{releaseBackup(hwnd);return}
 path,ok:=chooseBackup(hwnd)
 if !ok{return}
 msg:="Protéger cette copie de sauvegarde ?\n\n"+path+"\n\nWindows refusera les nouvelles ouvertures en écriture, suppression et renommage tant que le verrou reste actif.\n\nN'utilisez pas un coffre ou fichier actif. La fermeture de Sentinel libère le verrou. Ce n'est pas une protection générale du PC."
 decision,_,_:=messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16(msg))),uintptr(unsafe.Pointer(u16("Protection temporaire d'une copie"))),0x134)
 if decision!=6{return}
 lock,err:=sentinel.LockBackup(path)
 if err!=nil{
  messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Protection non activée : "+err.Error()))),uintptr(unsafe.Pointer(u16("Copie de sauvegarde"))),0x30)
  return
 }
 backupHandle=lock
 setLabel(backupLabel,"Copie verrouillée : "+filepath.Base(path)+" (jusqu'à libération ou fermeture).")
 setLabel(backupButton,"Libérer la copie")
 addLog("Copie verrouillée en lecture seule : "+filepath.Base(path))
}
