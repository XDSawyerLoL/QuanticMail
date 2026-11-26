//go:build windows

package vaultsession

import(
 "bufio"
 "bytes"
 "context"
 "crypto"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "errors"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "time"
 "unsafe"
)

// GraphicalBrokerConfig comes exclusively from trusted local enrollment.
// Neither the broker executable hash nor key pins may be obtained from the
// process being launched or chosen from an unauthenticated network reply.
type GraphicalBrokerConfig struct{
 Binary, BinarySHA256, VaultDirectory string
 SigningPin, EncryptionPin, RootPin string
 MachineID string
 Identity Identity
 Controller ed25519.PublicKey
}

func localAbsolute(p string)bool{
 return filepath.IsAbs(p)&&len(p)<=2048&&len(filepath.VolumeName(p))==2&&
 !strings.ContainsAny(p,"\x00\r\n")&&!strings.Contains(p[2:],":")&&filepath.Clean(p)==p
}
func safeBrokerPath(p string)error{
 if !localAbsolute(p){return errors.New("absolute local broker path required")}
 drive,err:=syscall.UTF16PtrFromString(filepath.VolumeName(p)+"\\")
 if err!=nil{return err}
 kind,_,_:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetDriveTypeW").Call(uintptr(unsafe.Pointer(drive)))
 if kind!=3{return errors.New("fixed local drive required")}
 for cur:=p;;cur=filepath.Dir(cur){
  ptr,err:=syscall.UTF16PtrFromString(cur);if err!=nil{return err}
  attr,err:=syscall.GetFileAttributes(ptr);if err!=nil{return err}
  if attr&0x400!=0{return errors.New("broker reparse path refused")}
  if filepath.Dir(cur)==cur{break}
 }
 return nil
}
func(c GraphicalBrokerConfig) args()([]string,error){
 if !localAbsolute(c.Binary)||!localAbsolute(c.VaultDirectory)||
 !strings.EqualFold(filepath.Ext(c.Binary),".exe")||
 !pinPattern.MatchString(c.BinarySHA256)||!pinPattern.MatchString(c.SigningPin)||
 !pinPattern.MatchString(c.EncryptionPin)||!pinPattern.MatchString(c.RootPin)||
 !addressPattern.MatchString(c.Identity.Address)||!devicePattern.MatchString(c.Identity.Device)||
 !pinPattern.MatchString(c.Identity.KEMPin)||!pinPattern.MatchString(c.Identity.DSAPin)||
 !machinePattern.MatchString(c.MachineID)||len(c.Controller)!=ed25519.PublicKeySize{
  return nil,errors.New("incomplete trusted graphical broker enrollment")
 }
 return []string{"--broker-windows-pq-quorum-gui-lab",c.VaultDirectory,
  base64.RawURLEncoding.EncodeToString(c.Controller),c.SigningPin,c.EncryptionPin,
  c.Identity.Address,c.Identity.Device,c.Identity.KEMPin,c.Identity.DSAPin,c.RootPin},nil
}

// Hold the pinned executable open read-only with neither write nor delete
// sharing through the child lifetime. This mitigates ordinary binary
// replacement, not hostile administrator/ancestor or DLL-directory attacks.
func pinGraphicalBroker(path,pin string)(*os.File,error){
 if err:=safeBrokerPath(path);err!=nil{return nil,err}
 ptr,err:=syscall.UTF16PtrFromString(path);if err!=nil{return nil,err}
 h,err:=syscall.CreateFile(ptr,syscall.GENERIC_READ,syscall.FILE_SHARE_READ,nil,syscall.OPEN_EXISTING,0x00200000,0)
 if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(h),path)
 if f==nil{syscall.CloseHandle(h);return nil,errors.New("broker handle invalid")}
 accepted:=false
 defer func(){if !accepted{f.Close()}}()
 var info syscall.ByHandleFileInformation
 if syscall.GetFileInformationByHandle(h,&info)!=nil||info.FileAttributes&(0x10|0x400)!=0{return nil,errors.New("broker not a regular file")}
 resolved:=make([]uint16,32768)
 k:=syscall.NewLazyDLL("kernel32.dll")
 n,_,_:=k.NewProc("GetFinalPathNameByHandleW").Call(uintptr(h),uintptr(unsafe.Pointer(&resolved[0])),uintptr(len(resolved)),0)
 if n==0||n>=uintptr(len(resolved))||!strings.EqualFold(strings.TrimPrefix(syscall.UTF16ToString(resolved[:n]),"\\\\?\\"),path){
  return nil,errors.New("broker resolved path mismatch")
 }
 digest:=sha256.New()
 count,err:=io.Copy(digest,io.LimitReader(f,128<<20+1))
 if err!=nil||count==0||count>128<<20||hex.EncodeToString(digest.Sum(nil))!=pin{return nil,errors.New("broker binary hash mismatch")}
 accepted=true
 return f,nil
}

// OpenGraphicalBroker starts only the existing native Vault graphical broker.
// The caller supplies the already enrolled controller signer; this adapter
// does not load private keys or request passphrases. Vault owns the graphical
// dialogs, encrypted storage, approvals and existing quorum checks.
// Successful return is one short-lived authenticated proof session, NOT a
// permanent login or permission to change OS settings. Caller must establish
// trusted installation/dependency custody and controller enrollment first.
func OpenGraphicalBroker(ctx context.Context,c GraphicalBrokerConfig,signer crypto.Signer)(*Session,error){
 if ctx==nil||signer==nil{return nil,errors.New("trusted controller and context required")}
 args,err:=c.args();if err!=nil{return nil,err}
 pub,ok:=signer.Public().(ed25519.PublicKey)
 if !ok||!bytes.Equal(pub,c.Controller){return nil,errors.New("controller differs from enrollment")}
 if !providerAvailable(){return nil,errors.New("ML-DSA verifier unavailable")}
 if err:=safeBrokerPath(c.VaultDirectory);err!=nil{return nil,err}
 info,err:=os.Stat(c.VaultDirectory);if err!=nil||!info.IsDir(){return nil,errors.New("Vault directory unavailable") }
 file,err:=pinGraphicalBroker(c.Binary,c.BinarySHA256);if err!=nil{return nil,err}
 defer file.Close()
 ctx,cancel:=context.WithTimeout(ctx,3*time.Minute);defer cancel()
 cmd:=exec.CommandContext(ctx,c.Binary,args...)
 cmd.Dir=filepath.Dir(c.Binary)
 cmd.SysProcAttr=&syscall.SysProcAttr{HideWindow:true,CreationFlags:0x08000000}
 // Do not inherit arbitrary DLL search paths or OpenSSL configuration.
 sys:=make([]uint16,32768)
 k:=syscall.NewLazyDLL("kernel32.dll")
 n,_,_:=k.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&sys[0])),uintptr(len(sys)))
 if n==0||n>=uintptr(len(sys)){return nil,errors.New("Windows system directory unavailable")}
 systemDir:=syscall.UTF16ToString(sys[:n])
 cmd.Env=[]string{"SystemRoot="+filepath.Dir(systemDir),"WINDIR="+filepath.Dir(systemDir),"PATH="+systemDir}
 in,err:=cmd.StdinPipe();if err!=nil{return nil,err}
 defer in.Close()
 out,err:=cmd.StdoutPipe();if err!=nil{return nil,err}
 defer out.Close()
 if err:=cmd.Start();err!=nil{return nil,err}
 defer func(){in.Close();out.Close();if cmd.Process!=nil{_ =cmd.Process.Kill()};_ =cmd.Wait()}()
 // Vault may require two graphical passphrases before it sends the hello.
 // Start the 30-second proof clock only AFTER that trusted unlock phase.
 reader:=bufio.NewReaderSize(out,maxBrokerLine)
 hello,err:=brokerLine(reader);if err!=nil{return nil,errors.New("graphical Vault unlock cancelled, refused or timed out")}
 s,err:=New(c.Identity,c.MachineID,time.Now());if err!=nil{return nil,err}
 // The overall unlock deadline is separate from the proof lifetime.
 // Closing the pipes and killing the child on expiry interrupts blocked IO.
 proofTimer:=time.AfterFunc(maxLifetime,func(){_ =cmd.Process.Kill()})
 defer proofTimer.Stop()
 if err:=ExchangeBrokerProof(io.MultiReader(bytes.NewReader(hello),reader),in,s,signer,c.Controller);err!=nil{return nil,err}
 if ctx.Err()!=nil{return nil,ctx.Err()}
 return s,nil
}
