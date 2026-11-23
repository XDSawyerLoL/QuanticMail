//go:build windows

package sentinel

import (
    "context"
    "encoding/binary"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "syscall"
    "time"
    "unicode/utf16"
    "unsafe"
)
const(
    fileListDirectory=0x0001
    actionAdded=1;actionRemoved=2;actionModified=3;actionRenamedOld=4;actionRenamedNew=5
)
var(
    kernel=syscall.NewLazyDLL("kernel32.dll")
    createEvent=kernel.NewProc("CreateEventW")
    getOverlappedResult=kernel.NewProc("GetOverlappedResult")
    resetEvent=kernel.NewProc("ResetEvent")
)
// Watch observes changes to an explicitly selected directory through
// ReadDirectoryChangesW. It cannot attribute changes to processes and does
// not block, kill or modify anything on the host.
func Watch(ctx context.Context,root string,out chan<-Event)error{
    if out==nil{return errors.New("event receiver required")}
    if !filepath.IsAbs(root){return errors.New("absolute directory required")}
    info,err:=os.Lstat(root)
    if err!=nil{return err}
    if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("a real directory is required")}
    ptr,err:=syscall.UTF16PtrFromString(root);if err!=nil{return err}
    handle,err:=syscall.CreateFile(ptr,fileListDirectory,
        syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,nil,
        syscall.OPEN_EXISTING,syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OVERLAPPED,0)
    if err!=nil{return fmt.Errorf("cannot start Windows directory notifications: %w",err)}
    defer syscall.CloseHandle(handle)
    eventRaw,_,callErr:=createEvent.Call(0,1,0,0)
    if eventRaw==0{return fmt.Errorf("cannot create watcher event: %v",callErr)}
    eventHandle:=syscall.Handle(eventRaw)
    defer syscall.CloseHandle(eventHandle)
    var buffer [64*1024]byte
    mask:=uint32(syscall.FILE_NOTIFY_CHANGE_FILE_NAME|syscall.FILE_NOTIFY_CHANGE_DIR_NAME|
        syscall.FILE_NOTIFY_CHANGE_LAST_WRITE|syscall.FILE_NOTIFY_CHANGE_SIZE)
    for{
        if ctx.Err()!=nil{return nil}
        reset,_,resetErr:=resetEvent.Call(uintptr(eventHandle))
        if reset==0{return fmt.Errorf("cannot reset watcher event: %v",resetErr)}
        ov:=syscall.Overlapped{HEvent:eventHandle}
        var count uint32
        err=syscall.ReadDirectoryChanges(handle,&buffer[0],uint32(len(buffer)),true,mask,&count,&ov,0)
        if err!=nil&&!errors.Is(err,syscall.ERROR_IO_PENDING){
            if ctx.Err()!=nil{return nil}
            return fmt.Errorf("directory notifications failed: %w",err)
        }
        if errors.Is(err,syscall.ERROR_IO_PENDING){
            cancelled:=false
            for{
                signal,waitErr:=syscall.WaitForSingleObject(eventHandle,200)
                if waitErr!=nil{return waitErr}
                if signal==syscall.WAIT_OBJECT_0{break}
                if signal!=syscall.WAIT_TIMEOUT{return errors.New("invalid Windows watcher wait result")}
                if ctx.Err()!=nil&&!cancelled{
                    _=syscall.CancelIoEx(handle,&ov)
                    cancelled=true
                }
            }
            result,_,getErr:=getOverlappedResult.Call(uintptr(handle),uintptr(unsafe.Pointer(&ov)),uintptr(unsafe.Pointer(&count)),0)
            if result==0{
                if ctx.Err()!=nil{return nil}
                return fmt.Errorf("Windows watcher operation failed: %v",getErr)
            }
        }
        runtime.KeepAlive(buffer)
        if ctx.Err()!=nil{return nil}
        if count==0{
            select{case out<-Event{Kind:Overflow,At:time.Now()}:case <-ctx.Done():return nil}
            continue
        }
        if count>uint32(len(buffer)){return errors.New("invalid event buffer length")}
        events,parseErr:=parseNotifications(root,buffer[:count],time.Now())
        if parseErr!=nil{return parseErr}
        for _,ev:=range events{select{case out<-ev:case <-ctx.Done():return nil}}
    }
}
func parseNotifications(root string,raw []byte,now time.Time)([]Event,error){
    events:=make([]Event,0,8)
    for off:=0;off<len(raw);{
        if len(raw)-off<12{return nil,errors.New("truncated change notification")}
        next:=int(binary.LittleEndian.Uint32(raw[off:]))
        action:=binary.LittleEndian.Uint32(raw[off+4:])
        bytesName:=int(binary.LittleEndian.Uint32(raw[off+8:]))
        if bytesName==0||bytesName%2!=0||bytesName>len(raw)-off-12{return nil,errors.New("invalid notification filename")}
        utf:=make([]uint16,bytesName/2)
        for i:=range utf{utf[i]=binary.LittleEndian.Uint16(raw[off+12+2*i:])}
        name:=string(utf16.Decode(utf))
        if name==""{return nil,errors.New("empty notification filename")}
        full:=filepath.Clean(filepath.Join(root,name))
        relative,err:=filepath.Rel(root,full)
        if err!=nil||relative==".."||filepath.IsAbs(relative)||
            (len(relative)>=3&&relative[:3]==".."+string(filepath.Separator)){
            return nil,errors.New("notification outside monitored directory")
        }
        kind:=Written
        switch action{
        case actionAdded:kind=Created
        case actionRemoved:kind=Removed
        case actionRenamedOld,actionRenamedNew:kind=Renamed
        case actionModified:kind=Written
        default:return nil,errors.New("unknown Windows notification action")
        }
        events=append(events,Event{Path:full,Kind:kind,At:now})
        if next==0{break}
        if next<12||next>len(raw)-off||next%4!=0{return nil,errors.New("invalid notification record chain")}
        off+=next
    }
    return events,nil
}
