//go:build windows

package sentinel

import(
 "bytes"
 "context"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "time"
 "unsafe"
)

const defenderReportScript = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
$module=Join-Path $PSHOME 'Modules\Defender\Defender.psd1'
Import-Module -Name $module -ErrorAction Stop
$p=Defender\Get-MpPreference -ErrorAction Stop
$s=Defender\Get-MpComputerStatus -ErrorAction Stop
if ($null -eq $p.EnableControlledFolderAccess -or $null -eq $s.AntivirusEnabled -or $null -eq $s.RealTimeProtectionEnabled) { throw 'Incomplete Defender report' }
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
@{mode=[int]$p.EnableControlledFolderAccess;antivirus=[bool]$s.AntivirusEnabled;realtime=[bool]$s.RealTimeProtectionEnabled;running_mode=[string]$s.AMRunningMode;default_folders=@($p.ControlledFolderAccessDefaultProtectedFolders | Where-Object {$_});extra_folders=@($p.ControlledFolderAccessProtectedFolders | Where-Object {$_})} | ConvertTo-Json -Compress -Depth 3`

type boundedReport struct{b bytes.Buffer}
func(w *boundedReport)Write(p []byte)(int,error){
 if w.b.Len()+len(p)>65536{return 0,errors.New("Defender report exceeds limit")}
 return w.b.Write(p)
}
func systemPowerShell()(string,error){
 buf:=make([]uint16,32768)
 proc:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")
 n,_,err:=proc.Call(uintptr(unsafe.Pointer(&buf[0])),uintptr(len(buf)))
 if n==0||n>=uintptr(len(buf)){return "",err}
 return filepath.Join(syscall.UTF16ToString(buf[:n]),"WindowsPowerShell","v1.0","powershell.exe"),nil
}
// ReadProtectionSnapshot queries the built-in Defender provider via a fixed
// read-only PowerShell script. No input interpolation, shell UI, elevation,
// policy changes, exclusions or downloaded scripts. Unavailable is explicit.
func ReadProtectionSnapshot(ctx context.Context)(ProtectionSnapshot,error){
 if ctx==nil{return ProtectionSnapshot{},errors.New("context required")}
 ctx,cancel:=context.WithTimeout(ctx,12*time.Second);defer cancel()
 exe,err:=systemPowerShell();if err!=nil{return ProtectionSnapshot{},err}
 cmd:=exec.CommandContext(ctx,exe,"-NoLogo","-NoProfile","-NonInteractive","-Command",defenderReportScript)
 cmd.SysProcAttr=&syscall.SysProcAttr{HideWindow:true,CreationFlags:0x08000000}
 cmd.Dir=filepath.Dir(exe)
 // Restrict module search to trusted built-in PowerShell modules. Preserve
 // the normal Windows environment but never inherit user PSModulePath.
 for _,v:=range os.Environ(){if !strings.HasPrefix(strings.ToUpper(v),"PSMODULEPATH="){cmd.Env=append(cmd.Env,v)}}
 cmd.Env=append(cmd.Env,"PSModulePath="+filepath.Join(filepath.Dir(exe),"Modules"))
 var out boundedReport
 cmd.Stdout=&out
 if err:=cmd.Run();err!=nil{return ProtectionSnapshot{},errors.New("Defender indisponible ou consultation refusée")}
 return ParseProtectionSnapshot(out.b.Bytes(),time.Now())
}
