//go:build windows

package sentinel
import("context";"testing";"time";"path/filepath";"strings")
func TestSystemDefenderReadOnlyProbe(t *testing.T){
 exe,err:=systemPowerShell();if err!=nil{t.Fatal(err)}
 if !filepath.IsAbs(exe)||!strings.EqualFold(filepath.Base(exe),"powershell.exe"){t.Fatal("invalid system executable")}
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
 snapshot,err:=ReadProtectionSnapshot(ctx)
 if err!=nil{t.Skipf("Defender provider not accessible in this environment: %v",err)}
 if snapshot.Mode==nil||snapshot.Antivirus==nil||snapshot.RealTime==nil||snapshot.CheckedAt.IsZero(){t.Fatal("incomplete report")}
 a:=AssessProtection(snapshot,"",time.Now())
 t.Logf("Defender mode=%d assessment=%s",*snapshot.Mode,a.State)
}
