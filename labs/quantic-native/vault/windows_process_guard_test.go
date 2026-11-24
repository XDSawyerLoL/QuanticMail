//go:build windows && cgo && pqopenssl

package main

import(
 "bufio"
 "context"
 "fmt"
 "io"
 "os"
 "os/exec"
 "syscall"
 "testing"
 "time"
)

// Tests only new process handles, not existing creator handles or debug
// privilege. The subprocess holds no real keys or personal data.
func TestWindowsCryptoProcessAccess(t *testing.T){
 if os.Getenv("QV_SYNTHETIC_PROCESS_ACCESS_CHILD")=="1"{
  if e:=winProtectCryptoProcess();e!=nil{t.Fatal(e)}
  fmt.Println("QV_READY")
  _,_=io.Copy(io.Discard,os.Stdin)
  return
 }
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 exe,e:=os.Executable();if e!=nil{t.Fatal(e)}
 cmd:=exec.CommandContext(ctx,exe,"-test.run=^TestWindowsCryptoProcessAccess$")
 cmd.Env=append(os.Environ(),"QV_SYNTHETIC_PROCESS_ACCESS_CHILD=1")
 in,e:=cmd.StdinPipe();if e!=nil{t.Fatal(e)}
 out,e:=cmd.StdoutPipe();if e!=nil{t.Fatal(e)}
 cmd.Stderr=os.Stderr
 if e=cmd.Start();e!=nil{t.Fatal(e)}
 defer func(){in.Close();cmd.Wait()}()
 line,e:=bufio.NewReader(out).ReadString('\n');if e!=nil||line!="QV_READY\n"{t.Fatal("child protection not established",line,e)}
 pid:=uint32(cmd.Process.Pid)
 for _,access:=range []uint32{0x10,0x20,0x8,0x40,0x2,0x40000,0x80000}{
  h,e:=syscall.OpenProcess(access,false,pid)
  if e==nil{syscall.CloseHandle(h);t.Fatalf("unexpected new process access: %#x",access)}
  if e!=syscall.ERROR_ACCESS_DENIED{t.Fatalf("unexpected refusal %#x: %v",access,e)}
 }
 h,e:=syscall.OpenProcess(0x1000|0x100000,false,pid)
 if e!=nil{t.Fatal("normal query/wait access refused",e)}
 syscall.CloseHandle(h)
}
