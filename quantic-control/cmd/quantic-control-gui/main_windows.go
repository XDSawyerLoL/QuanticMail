//go:build windows

package main

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "os"
    "path/filepath"
    "runtime"
    "syscall"
    "unsafe"
)

const (
    wmCreate = 0x0001
    wmDestroy = 0x0002
    wmCommand = 0x0111
    wmSetFont = 0x0030
    wsChild = 0x40000000
    wsVisible = 0x10000000
    wsOverlappedWindow = 0x00CF0000
    bsPushbutton = 0
    colorWindow = 5
    defaultGUIFont = 17
    cmdChoose = 101
    cmdRescan = 102
    cmdReset = 103
    ofnExplorer = 0x00080000
    ofnFileMustExist = 0x00001000
    ofnPathMustExist = 0x00000800
    ofnNoChangeDir = 0x00000008
    maxInspectBytes = 32 << 20
)

type point struct { x,y int32 }
type message struct { hwnd uintptr; msg uint32; wParam, lParam uintptr; time uint32; pt point; private uint32 }
type windowClassEx struct {
    size, style uint32
    callback uintptr
    classExtra, windowExtra int32
    instance, icon, cursor, background uintptr
    menuName, className *uint16
    iconSmall uintptr
}
type openFileName struct {
    size uint32
    owner, instance uintptr
    filter, customFilter *uint16
    maxCustomFilter, filterIndex uint32
    file *uint16
    maxFile uint32
    fileTitle *uint16
    maxFileTitle uint32
    initialDir, title *uint16
    flags uint32
    fileOffset, fileExtension uint16
    defaultExtension *uint16
    customData, hook uintptr
    templateName *uint16
    reserved uintptr
    reservedCode, extendedFlags uint32
}

var (
    u32 = syscall.NewLazyDLL("user32.dll")
    k32 = syscall.NewLazyDLL("kernel32.dll")
    gdi32 = syscall.NewLazyDLL("gdi32.dll")
    dlg = syscall.NewLazyDLL("comdlg32.dll")
    registerClass = u32.NewProc("RegisterClassExW")
    createWindow = u32.NewProc("CreateWindowExW")
    defWindowProc = u32.NewProc("DefWindowProcW")
    getMessage = u32.NewProc("GetMessageW")
    translateMessage = u32.NewProc("TranslateMessage")
    dispatchMessage = u32.NewProc("DispatchMessageW")
    postQuit = u32.NewProc("PostQuitMessage")
    setText = u32.NewProc("SetWindowTextW")
    sendMessage = u32.NewProc("SendMessageW")
    messageBox = u32.NewProc("MessageBoxW")
    chooseFile = dlg.NewProc("GetOpenFileNameW")
    statusLabel uintptr
    selectedPath, originalDigest string
)

func utf16(s string)*uint16 { return syscall.StringToUTF16Ptr(s) }

func control(parent uintptr, class,title string,x,y,w,h int32,id uintptr) uintptr {
    inst,_,_:=k32.NewProc("GetModuleHandleW").Call(0)
    hwnd,_,_:=createWindow.Call(0,uintptr(unsafe.Pointer(utf16(class))),uintptr(unsafe.Pointer(utf16(title))),
        uintptr(wsChild|wsVisible|bsPushbutton),uintptr(x),uintptr(y),uintptr(w),uintptr(h),parent,id,inst,0)
    font,_,_:=gdi32.NewProc("GetStockObject").Call(defaultGUIFont)
    if hwnd!=0 { sendMessage.Call(hwnd,wmSetFont,font,1) }
    return hwnd
}

func changeStatus(text string) {
    if statusLabel!=0 {setText.Call(statusLabel,uintptr(unsafe.Pointer(utf16(text))))}
}

func pickPath(owner uintptr) (string,bool) {
    var file [32768]uint16
    title:=utf16("Choisir un fichier pour vérifier son intégrité")
    filter:=utf16("Tous les fichiers\x00*.*\x00\x00")
    params:=openFileName{
        size:uint32(unsafe.Sizeof(openFileName{})),owner:owner,filter:filter,
        file:&file[0],maxFile:uint32(len(file)),title:title,
        flags:ofnExplorer|ofnFileMustExist|ofnPathMustExist|ofnNoChangeDir,
    }
    result,_,_:=chooseFile.Call(uintptr(unsafe.Pointer(&params)))
    runtime.KeepAlive(params)
    runtime.KeepAlive(file)
    if result==0{return "",false}
    return syscall.UTF16ToString(file[:]),true
}

func fingerprint(path string)(string,error) {
    before,err:=os.Lstat(path)
    if err!=nil{return "",err}
    if !before.Mode().IsRegular() || before.Size()>maxInspectBytes {
        return "",errors.New("seuls les fichiers normaux de 32 Mo maximum sont acceptés")
    }
    f,err:=os.Open(path);if err!=nil{return "",err};defer f.Close()
    opened,err:=f.Stat()
    if err!=nil{return "",err}
    if !opened.Mode().IsRegular() || !os.SameFile(before,opened) {return "",errors.New("le fichier a changé pendant son ouverture")}
    hash:=sha256.New()
    n,err:=io.Copy(hash,io.LimitReader(f,maxInspectBytes+1))
    if err!=nil{return "",err}
    if n>maxInspectBytes{return "",errors.New("le fichier dépasse 32 Mo")}
    return hex.EncodeToString(hash.Sum(nil)),nil
}

func notify(hwnd uintptr,msg string) {
    messageBox.Call(hwnd,uintptr(unsafe.Pointer(utf16(msg))),uintptr(unsafe.Pointer(utf16("Quantic Control — Alpha"))),0x40)
}

func windowProc(hwnd uintptr, msg uint32, wparam,lparam uintptr)uintptr {
    switch msg {
    case wmCreate:
        control(hwnd,"STATIC","QUANTIC CONTROL  ·  ALPHA WINDOWS",22,16,570,32,0)
        control(hwnd,"STATIC","Observation locale uniquement — aucune protection antivirus ou contrôle distant actif.",22,57,560,43,0)
        statusLabel=control(hwnd,"STATIC","Aucun fichier sélectionné. Choisissez un fichier à vérifier.",22,111,555,70,0)
        control(hwnd,"BUTTON","Choisir un fichier",22,205,175,38,cmdChoose)
        control(hwnd,"BUTTON","Revérifier",209,205,150,38,cmdRescan)
        control(hwnd,"BUTTON","Oublier",370,205,130,38,cmdReset)
        control(hwnd,"STATIC","Les empreintes restent en mémoire, uniquement pour cette session.",22,264,560,39,0)
        return 0
    case wmCommand:
        switch wparam&0xffff {
        case cmdChoose:
            path,ok:=pickPath(hwnd);if !ok{return 0}
            digest,err:=fingerprint(path)
            if err!=nil{notify(hwnd,"Impossible de lire ce fichier : "+err.Error());return 0}
            selectedPath,originalDigest=path,digest
            changeStatus("Référence locale mémorisée : "+filepath.Base(path)+". Cliquez sur Revérifier pour détecter un changement.")
        case cmdRescan:
            if selectedPath=="" {notify(hwnd,"Choisissez d'abord un fichier.");return 0}
            digest,err:=fingerprint(selectedPath)
            if err!=nil {changeStatus("Impossible de vérifier le fichier : "+err.Error());return 0}
            if digest!=originalDigest {changeStatus("MODIFICATION DÉTECTÉE : "+filepath.Base(selectedPath)+" ne correspond plus à la référence.")
            } else {changeStatus("Aucune modification détectée depuis la sélection : "+filepath.Base(selectedPath)+". Cela ne prouve pas l'absence de malware.")}
        case cmdReset:
            selectedPath,originalDigest="",""
            changeStatus("Référence effacée de la mémoire de cette session.")
        }
        return 0
    case wmDestroy:
        postQuit.Call(0)
        return 0
    }
    result,_,_:=defWindowProc.Call(hwnd,uintptr(msg),wparam,lparam)
    return result
}

func main() {
    instance,_,_:=k32.NewProc("GetModuleHandleW").Call(0)
    className:=utf16("QuanticControlLocalAlpha")
    wc:=windowClassEx{size:uint32(unsafe.Sizeof(windowClassEx{})),callback:syscall.NewCallback(windowProc),
        instance:instance,background:colorWindow+1,className:className}
    result,_,_:=registerClass.Call(uintptr(unsafe.Pointer(&wc)))
    if result==0 {notify(0,"La fenêtre de Quantic Control n'a pas pu démarrer.");return}
    window,_,_:=createWindow.Call(0,uintptr(unsafe.Pointer(className)),uintptr(unsafe.Pointer(utf16("Quantic Control — Sécurité locale (Alpha)"))),
        wsOverlappedWindow|wsVisible,180,150,625,370,0,0,instance,0)
    if window==0 {notify(0,"La fenêtre de Quantic Control n'a pas pu être créée.");return}
    var msg message
    for {
        code,_,_:=getMessage.Call(uintptr(unsafe.Pointer(&msg)),0,0,0)
        if int32(code)<=0 {break}
        translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
        dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
    }
    selectedPath,originalDigest="",""
}
