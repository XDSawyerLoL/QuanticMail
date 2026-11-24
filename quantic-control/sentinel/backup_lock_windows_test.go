//go:build windows

package sentinel

import(
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "syscall"
 "testing"
)

func TestWindowsBackupLockCrossProcess(t *testing.T){
 path:=filepath.Join(t.TempDir(),"archive.bak")
 if err:=os.WriteFile(path,[]byte("original backup"),0600);err!=nil{t.Fatal(err)}
 lock,err:=LockBackup(path)
 if err!=nil{t.Fatal(err)}
 defer lock.Close()
 check:=func(mode string){
  t.Helper()
  cmd:=exec.Command(os.Args[0],"-test.run=^TestBackupLockChild$")
  cmd.Env=append(os.Environ(),"QUANTIC_BACKUP_LOCK_CHILD="+mode,"QUANTIC_BACKUP_LOCK_PATH="+path)
  if raw,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("independent process (%s): %v\n%s",mode,err,raw)}
 }
 check("locked")
 raw,err:=os.ReadFile(path)
 if err!=nil||string(raw)!="original backup"{t.Fatalf("backup altered: %q %v",raw,err)}
 if err:=lock.Close();err!=nil{t.Fatal(err)}
 if err:=lock.Close();err!=nil{t.Fatal("release not idempotent",err)}
 check("released")
 if _,err:=os.Stat(path);!errors.Is(err,os.ErrNotExist){t.Fatalf("released copy could not be renamed: %v",err)}
 raw,err=os.ReadFile(path+".renamed")
 if err!=nil||string(raw)!="allowed after release"{t.Fatalf("release did not restore normal access: %q %v",raw,err)}
}

func TestBackupLockChild(t *testing.T){
 mode:=os.Getenv("QUANTIC_BACKUP_LOCK_CHILD")
 if mode==""{return}
 path:=os.Getenv("QUANTIC_BACKUP_LOCK_PATH")
 if !filepath.IsAbs(path)||filepath.Base(path)!="archive.bak"{t.Fatal("invalid test fixture")}
 switch mode{
 case "locked":
  b,err:=os.ReadFile(path)
  if err!=nil||string(b)!="original backup"{t.Fatalf("reader failed: %q %v",b,err)}
  f,err:=os.OpenFile(path,os.O_WRONLY,0600)
  if err==nil{f.Close();t.Fatal("new writer opened locked backup")}
  if !errors.Is(err,syscall.Errno(32)){t.Fatalf("expected OS sharing violation, got %v",err)}
  if err:=os.Rename(path,path+".renamed");err==nil{t.Fatal("rename allowed")}
  if err:=os.Remove(path);err==nil{t.Fatal("delete allowed")}
 case "released":
  if err:=os.WriteFile(path,[]byte("allowed after release"),0600);err!=nil{t.Fatal(err)}
  if err:=os.Rename(path,path+".renamed");err!=nil{t.Fatal(err)}
 default:t.Fatal("invalid child mode")
 }
}
func TestBackupLockRejectsExistingWriterAndNonBackup(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"copy.bak")
 if err:=os.WriteFile(path,[]byte("test"),0600);err!=nil{t.Fatal(err)}
 writer,err:=os.OpenFile(path,os.O_WRONLY,0600)
 if err!=nil{t.Fatal(err)}
 defer writer.Close()
 if l,err:=LockBackup(path);err==nil{l.Close();t.Fatal("existing writer accepted")}
 for _,p:=range []string{filepath.Join(dir,"live.exe"),dir,"relative.bak",path+":stream.bak"}{
  if l,err:=LockBackup(p);err==nil{l.Close();t.Fatalf("unsafe target accepted: %s",p)}
 }
}
