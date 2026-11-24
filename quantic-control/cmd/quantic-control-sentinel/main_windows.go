//go:build windows
// Quantic Sentinel is an opt-in, on-screen Windows folder activity monitor.
// No persistent service, remote shell, process termination or OS security change.
package main

import(
 "context"
 "fmt"
 "os"
 "path/filepath"
 "sync"
 "syscall"
 "time"
 "unsafe"
 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)
const(
 wmCreate=0x0001;wmDestroy=0x0002;wmCommand=0x0111;wmSetFont=0x0030;wmAppUpdate=0x8001
 wsChild=0x40000000;wsVisible=0x10000000;wsOverlappedWindow=0x00CF0000
 wsVScroll=0x00200000;wsBorder=0x00800000;lbsNotify=0x0001
 lbAddString=0x0180;lbSetTopIndex=0x0197;lbResetContent=0x0184
 cmdSelect=201;cmdStop=202;cmdClear=203;cmdInstall=204;cmdUninstall=205;cmdHistory=206;cmdDefender=207
 colorWindow=5;defaultGuiFont=17
 bifReturnOnlyFSDirs=1;bifEditBox=0x10;bifNewDialogStyle=0x40
)
type point struct{x,y int32}
type message struct{hwnd uintptr;msg uint32;wparam,lparam uintptr;time uint32;pt point;private uint32}
type windowClassEx struct{
 size,style uint32;callback uintptr;classExtra,windowExtra int32
 instance,icon,cursor,background uintptr;menuName,className *uint16;iconSmall uintptr
}
type browseInfo struct{
 owner,root uintptr;displayName *uint16;title *uint16;flags uint32;callback,lparam uintptr;image int32
}
type update struct{kind,description string;alert *sentinel.Alert;count uint64}
var(
 user32=syscall.NewLazyDLL("user32.dll")
 kernel32=syscall.NewLazyDLL("kernel32.dll")
 shell32=syscall.NewLazyDLL("shell32.dll")
 ole32=syscall.NewLazyDLL("ole32.dll")
 gdi32=syscall.NewLazyDLL("gdi32.dll")
 registerClass=user32.NewProc("RegisterClassExW")
 createWindow=user32.NewProc("CreateWindowExW")
 defWindowProc=user32.NewProc("DefWindowProcW")
 getMessage=user32.NewProc("GetMessageW")
 translateMessage=user32.NewProc("TranslateMessage")
 dispatchMessage=user32.NewProc("DispatchMessageW")
 postQuit=user32.NewProc("PostQuitMessage")
 postMessage=user32.NewProc("PostMessageW")
 setText=user32.NewProc("SetWindowTextW")
 sendMessage=user32.NewProc("SendMessageW")
 enableWindow=user32.NewProc("EnableWindow")
 messageBox=user32.NewProc("MessageBoxW")
 browseForFolder=shell32.NewProc("SHBrowseForFolderW")
 getPathFromID=shell32.NewProc("SHGetPathFromIDListW")
 coTaskMemFree=ole32.NewProc("CoTaskMemFree")
 statusLabel,folderLabel,statsLabel,activityList,stopButton uintptr
 monitorCancel context.CancelFunc
 uiQueue []update
 uiMu sync.Mutex
 totalEvents uint64
 selectedRoot string
)
func u16(v string)*uint16{return syscall.StringToUTF16Ptr(v)}
func classStyle(class string)uint32{if class=="LISTBOX"{return wsBorder|wsVScroll|lbsNotify};return 0}
func makeControl(parent uintptr,class,title string,x,y,w,h int32,id uintptr)uintptr{
 instance,_,_:=kernel32.NewProc("GetModuleHandleW").Call(0)
 hwnd,_,_:=createWindow.Call(0,uintptr(unsafe.Pointer(u16(class))),uintptr(unsafe.Pointer(u16(title))),
    uintptr(wsChild|wsVisible|classStyle(class)),uintptr(x),uintptr(y),uintptr(w),uintptr(h),parent,id,instance,0)
 font,_,_:=gdi32.NewProc("GetStockObject").Call(defaultGuiFont)
 if hwnd!=0{sendMessage.Call(hwnd,wmSetFont,font,1)}
 return hwnd
}
func setLabel(hwnd uintptr,text string){if hwnd!=0{setText.Call(hwnd,uintptr(unsafe.Pointer(u16(text))))}}
func chooseFolder(owner uintptr)(string,bool){
 var display [260]uint16
 title:=u16("Choisissez un dossier dont vous autorisez la surveillance")
 info:=browseInfo{owner:owner,displayName:&display[0],title:title,flags:bifReturnOnlyFSDirs|bifEditBox|bifNewDialogStyle}
 pidl,_,_:=browseForFolder.Call(uintptr(unsafe.Pointer(&info)))
 if pidl==0{return "",false}
 defer coTaskMemFree.Call(pidl)
 var buf [32768]uint16
 ok,_,_:=getPathFromID.Call(pidl,uintptr(unsafe.Pointer(&buf[0])))
 if ok==0{return "",false}
 path:=syscall.UTF16ToString(buf[:])
 return path,path!=""
}
func addLog(text string){
 if activityList==0{return}
 index,_,_:=sendMessage.Call(activityList,lbAddString,0,uintptr(unsafe.Pointer(u16(text))))
 sendMessage.Call(activityList,lbSetTopIndex,index,0)
}
func enqueue(hwnd uintptr,u update){
 uiMu.Lock()
 if len(uiQueue)>=400{uiQueue=uiQueue[1:]}
 uiQueue=append(uiQueue,u)
 uiMu.Unlock()
 postMessage.Call(hwnd,wmAppUpdate,0,0)
}
func stopMonitor(){
 if monitorCancel!=nil{monitorCancel();monitorCancel=nil}
 enableWindow.Call(stopButton,0)
}
func startMonitor(hwnd uintptr,root string){
 stopMonitor()
 totalEvents=0
 ctx,cancel:=context.WithCancel(context.Background())
 monitorCancel=cancel
 setLabel(folderLabel,"Dossier : "+root)
 setLabel(statusLabel,"SURVEILLANCE ACTIVÉE — alertes uniquement, aucune modification des fichiers")
 setLabel(statsLabel,"Événements : 0 | Alertes : observation")
 enableWindow.Call(stopButton,1)
 addLog(time.Now().Format("15:04:05")+"  Surveillance activée : "+filepath.Base(root))
 events:=make(chan sentinel.Event,256)
 detector:=sentinel.NewDetector(sentinel.DefaultPolicy())
 go func(){
   err:=sentinel.Watch(ctx,root,events)
   if err!=nil&&ctx.Err()==nil{enqueue(hwnd,update{kind:"error",description:err.Error()})}
   close(events)
 }()
 go func(){
   var counter uint64
   for e:=range events{
     if ctx.Err()!=nil{return}
     counter++
     if a:=detector.Observe(e);a!=nil{enqueue(hwnd,update{kind:"alert",alert:a,count:counter})
     }else if counter==1||counter%15==0{enqueue(hwnd,update{kind:"activity",count:counter,description:filepath.Base(e.Path)})}
   }
 }()
}
func drain(hwnd uintptr){
 uiMu.Lock();items:=uiQueue;uiQueue=nil;uiMu.Unlock()
 for _,item:=range items{
   if item.count>totalEvents{totalEvents=item.count}
   switch item.kind{
   case "activity":
     setLabel(statsLabel,fmt.Sprintf("Événements : %d | surveillance en cours",totalEvents))
   case "error":
     stopMonitor()
     setLabel(statusLabel,"SURVEILLANCE ARRÊTÉE — erreur d'accès ou dossier indisponible")
     addLog("ERREUR DE SURVEILLANCE : "+item.description)
     messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Le dossier ne peut plus être surveillé : "+item.description))),uintptr(unsafe.Pointer(u16("Quantic Sentinel — erreur"))),0x30)
   case "alert":
     a:=item.alert;if a==nil{continue}
     msg:=fmt.Sprintf("%s — %d fichiers distincts en %d événements.",a.Rule,a.UniqueFiles,a.Count)
     addLog("ALERTE "+a.Time.Format("15:04:05")+" : "+msg)
     setLabel(statsLabel,fmt.Sprintf("ALERTE D'ACTIVITÉ | %d événements observés",totalEvents))
     messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16(msg+"\n\nCette alerte indique un comportement inhabituel, pas une infection confirmée.\nQuantic Sentinel ne bloque pas encore les processus."))),uintptr(unsafe.Pointer(u16("Quantic Sentinel — activité inhabituelle"))),0x30)
   }
 }
}
func wndProc(hwnd uintptr,msg uint32,wparam,lparam uintptr)uintptr{
 switch msg{
 case wmCreate:
   makeControl(hwnd,"STATIC","QUANTIC SILLAGE   /   SENTINEL",22,18,730,36,0)
   makeControl(hwnd,"STATIC","Surveillance des modifications suspectes. Détection, pas blocage automatique.",22,62,700,30,0)
   statusLabel=makeControl(hwnd,"STATIC","Surveillance inactive — sélectionnez un dossier pour commencer.",22,115,730,32,0)
   folderLabel=makeControl(hwnd,"STATIC","Aucun dossier sélectionné",22,154,730,47,0)
   makeControl(hwnd,"BUTTON","Surveiller un dossier",22,225,225,40,cmdSelect)
   stopButton=makeControl(hwnd,"BUTTON","Arrêter",258,225,140,40,cmdStop)
   enableWindow.Call(stopButton,0)
   makeControl(hwnd,"BUTTON","Effacer le journal",408,225,180,40,cmdClear)
   makeControl(hwnd,"BUTTON","Installer pour ma session Windows",22,279,270,40,cmdInstall)
   makeControl(hwnd,"BUTTON","Désinstaller",304,279,155,40,cmdUninstall)
   makeControl(hwnd,"BUTTON","Historique local",471,279,190,40,cmdHistory)
   statsLabel=makeControl(hwnd,"STATIC","Événements : 0",22,334,700,28,0)
   makeControl(hwnd,"STATIC","Activité et alertes (session courante ou historisées)",22,373,700,28,0)
   activityList=makeControl(hwnd,"LISTBOX","",22,409,722,190,0)
   makeControl(hwnd,"STATIC","Agent volontaire au prochain login. Pas de réseau. Microsoft Defender reste actif.",22,610,730,34,0)
   makeControl(hwnd,"BUTTON","Protection antirançongiciel Windows",22,650,360,38,cmdDefender)
   return 0
 case wmCommand:
   switch wparam&0xffff{
   case cmdSelect:
     path,ok:=chooseFolder(hwnd)
     if ok{selectedRoot=path;startMonitor(hwnd,path)}
   case cmdStop:
     stopMonitor();setLabel(statusLabel,"SURVEILLANCE ARRÊTÉE")
     addLog(time.Now().Format("15:04:05")+"  Surveillance arrêtée")
   case cmdClear:if activityList!=0{sendMessage.Call(activityList,lbResetContent,0,0)}
   case cmdInstall:
     if selectedRoot=="" {
       path,ok:=chooseFolder(hwnd)
       if !ok{return 0}
       selectedRoot=path
     }
     if err:=installResident(selectedRoot);err!=nil{
       messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Installation refusée : "+err.Error()))),
         uintptr(unsafe.Pointer(u16("Quantic Sentinel — installation"))),0x30)
     }else{
       setLabel(statusLabel,"AGENT UTILISATEUR INSTALLÉ — démarrage à l'ouverture de votre session")
       addLog("Installation volontaire. Le moniteur reste actif après fermeture de cette fenêtre.")
       messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Agent installé pour votre compte Windows.\nIl démarre à l'ouverture de session et journalise localement les alertes.\n\nAucun privilège administrateur n'est requis.\nLe programme reste expérimental : il ne bloque pas les rançongiciels."))),
        uintptr(unsafe.Pointer(u16("Quantic Sentinel — installation"))),0x40)
     }
   case cmdUninstall:
     if err:=uninstallResident();err!=nil{
       messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Désinstallation non terminée : "+err.Error()))),
        uintptr(unsafe.Pointer(u16("Quantic Sentinel — désinstallation"))),0x30)
     }else{
       addLog("Démarrage automatique supprimé. Agent arrêté et fichiers du programme retirés.")
       setLabel(statusLabel,"AGENT UTILISATEUR DÉSINSTALLÉ — les journaux locaux sont conservés")
     }
   case cmdDefender:
     // Open existing Windows protections; never change antivirus settings
     // or add any Defender exclusions automatically.
     target:=u16("windowsdefender://ransomwareprotection/")
     open:=u16("open")
     shellResult,_,_:=shell32.NewProc("ShellExecuteW").Call(hwnd,uintptr(unsafe.Pointer(open)),uintptr(unsafe.Pointer(target)),0,0,1)
     if shellResult<=32{
       messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16("Ouvrez Sécurité Windows > Protection contre les virus et menaces > Protection contre les rançongiciels.\nVérifiez l'accès contrôlé aux dossiers. L'activation reste votre décision."))),
         uintptr(unsafe.Pointer(u16("Protection Windows"))),0x40)
     }
   case cmdHistory:
     path,err:=auditPath()
     if err!=nil{addLog("Impossible de localiser les journaux : "+err.Error());return 0}
     records,err:=sentinel.RecentRecords(path,35)
     if err!=nil{
       if os.IsNotExist(err){addLog("Aucun historique disponible : installez puis démarrez l'agent.")
       }else{addLog("Journal indisponible : "+err.Error())}
       return 0
     }
     addLog("--- Historique de l'agent résident (local) ---")
     for _,record:=range records{
       at:=record.Time.Local().Format("02/01 15:04:05")
       addLog(at+" ["+record.Type+"] "+record.Message)
     }
   }
   return 0
 case wmAppUpdate:drain(hwnd);return 0
 case wmDestroy:stopMonitor();postQuit.Call(0);return 0
 }
 ret,_,_:=defWindowProc.Call(hwnd,uintptr(msg),wparam,lparam)
 return ret
}
func main(){
 if len(os.Args)==2&&os.Args[1]=="--resident"{
   // Non-interactive per-user agent; errors are not hidden by fallback modes.
   _=residentAgent()
   return
 }
 ole32.NewProc("CoInitializeEx").Call(0,2)
 defer ole32.NewProc("CoUninitialize").Call()
 instance,_,_:=kernel32.NewProc("GetModuleHandleW").Call(0)
 class:=u16("QuanticSentinelAlphaNative")
 wc:=windowClassEx{size:uint32(unsafe.Sizeof(windowClassEx{})),instance:instance,className:class,
   callback:syscall.NewCallback(wndProc),background:colorWindow+1}
 valid,_,_:=registerClass.Call(uintptr(unsafe.Pointer(&wc)))
 if valid==0{return}
 hwnd,_,_:=createWindow.Call(0,uintptr(unsafe.Pointer(class)),uintptr(unsafe.Pointer(u16("Quantic Sillage — Sentinel Alpha"))),
   wsOverlappedWindow|wsVisible,180,100,780,810,0,0,instance,0)
 if hwnd==0{return}
 var msg message
 for{
   ret,_,_:=getMessage.Call(uintptr(unsafe.Pointer(&msg)),0,0,0)
   if int32(ret)<=0{break}
   translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
   dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
 }
}
