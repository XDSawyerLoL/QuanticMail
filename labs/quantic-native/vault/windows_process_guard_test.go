//go:build windows && cgo && pqopenssl

package main

import(
 "bufio"
 stdcontext "context"
 "fmt"
 "io"
 "os"
 "os/exec"
 "strconv"
 "syscall"
 "testing"
 "time"
 "unsafe"
)

// A separate probe process disables its own token privileges only. The
// GitHub runner may start with SeDebugPrivilege enabled, which bypasses DACLs.
// Neither the real vault nor the parent test token is changed.
func winOrdinaryProbeToken(t *testing.T){
 process,e:=syscall.GetCurrentProcess();if e!=nil{t.Fatal(e)}
 var token syscall.Token
 if e=syscall.OpenProcessToken(process,syscall.TOKEN_QUERY|syscall.TOKEN_ADJUST_PRIVILEGES,&token);e!=nil{t.Fatal(e)}
 defer token.Close()
 user,e:=token.GetTokenUser();if e!=nil{t.Fatal(e)}
 sid,e:=user.User.Sid.String();if e!=nil{t.Fatal(e)}
 if sid=="S-1-5-18"{t.Fatal("ordinary-process test cannot run as SYSTEM")}
 advapi:=syscall.NewLazyDLL("advapi32.dll")
 lookup:=advapi.NewProc("LookupPrivilegeValueW")
 check:=advapi.NewProc("PrivilegeCheck")
 adjust:=advapi.NewProc("AdjustTokenPrivileges")
 // PRIVILEGE_SET with one LUID_AND_ATTRIBUTES.
 type privilegeSet struct{ Count,Control,LowPart,HighPart,Attributes uint32 }
 p:=privilegeSet{Count:1,Control:1,Attributes:2}
 name,e:=syscall.UTF16PtrFromString("SeDebugPrivilege");if e!=nil{t.Fatal(e)}
 ok,_,err:=lookup.Call(0,uintptr(unsafe.Pointer(name)),uintptr(unsafe.Pointer(&p.LowPart)))
 if ok==0{t.Fatal("debug privilege lookup",err)}
 var enabled int32
 ok,_,err=check.Call(uintptr(token),uintptr(unsafe.Pointer(&p)),uintptr(unsafe.Pointer(&enabled)))
 if ok==0{t.Fatal("initial privilege check",err)}
 t.Logf("probe debug privilege enabled before restriction: %t",enabled!=0)
 ok,_,err=adjust.Call(uintptr(token),1,0,0,0,0)
 if ok==0{t.Fatal("disable probe privileges",err)}
 p.Attributes=2;enabled=0
 ok,_,err=check.Call(uintptr(token),uintptr(unsafe.Pointer(&p)),uintptr(unsafe.Pointer(&enabled)))
 if ok==0||enabled!=0{t.Fatal("probe debug privilege still enabled or unverifiable",err)}
}

func TestWindowsCryptoProcessAccess(t *testing.T){
 switch os.Getenv("QV_SYNTHETIC_PROCESS_ACCESS_CHILD"){
 case "target":
  if e:=winProtectCryptoProcess();e!=nil{t.Fatal(e)}
  fmt.Println("QV_READY")
  _,_=io.Copy(io.Discard,os.Stdin)
  return
 case "probe":
  winOrdinaryProbeToken(t)
  n,e:=strconv.ParseUint(os.Getenv("QV_SYNTHETIC_PROCESS_ACCESS_PID"),10,32);if e!=nil||n==0{t.Fatal("invalid synthetic PID")}
  pid:=uint32(n)
  for _,access:=range []uint32{0x10,0x20,0x8,0x40,0x2,0x40000,0x80000}{
   h,e:=syscall.OpenProcess(access,false,pid)
   if e==nil{syscall.CloseHandle(h);t.Fatalf("unexpected ordinary process access: %#x",access)}
   if e!=syscall.ERROR_ACCESS_DENIED{t.Fatalf("unexpected refusal %#x: %v",access,e)}
  }
  h,e:=syscall.OpenProcess(0x1000|0x100000,false,pid)
  if e!=nil{t.Fatal("normal query/wait access refused",e)}
  syscall.CloseHandle(h)
  t.Log("all seven forbidden access masks refused; query/wait allowed")
  return
 }
 ctx,cancel:=stdcontext.WithTimeout(stdcontext.Background(),20*time.Second);defer cancel()
 exe,e:=os.Executable();if e!=nil{t.Fatal(e)}
 cmd:=exec.CommandContext(ctx,exe,"-test.run=^TestWindowsCryptoProcessAccess$")
 cmd.Env=append(os.Environ(),"QV_SYNTHETIC_PROCESS_ACCESS_CHILD=target")
 in,e:=cmd.StdinPipe();if e!=nil{t.Fatal(e)}
 out,e:=cmd.StdoutPipe();if e!=nil{t.Fatal(e)}
 cmd.Stderr=os.Stderr
 if e=cmd.Start();e!=nil{t.Fatal(e)}
 defer func(){in.Close();cmd.Wait()}()
 line,e:=bufio.NewReader(out).ReadString('\n');if e!=nil||line!="QV_READY\n"{t.Fatal("child protection not established",line,e)}
 probe:=exec.CommandContext(ctx,exe,"-test.v","-test.run=^TestWindowsCryptoProcessAccess$")
 probe.Env=append(os.Environ(),"QV_SYNTHETIC_PROCESS_ACCESS_CHILD=probe","QV_SYNTHETIC_PROCESS_ACCESS_PID="+strconv.Itoa(cmd.Process.Pid))
 result,e:=probe.CombinedOutput()
 t.Log(string(result))
 if e!=nil{t.Fatal("independent ordinary process probe failed",e)}
}
