//go:build windows && cgo && pqopenssl

package main
import(
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestWindowsScatteringEpochGuard(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"transport")
 if e:=winCreateScattering(dir);e!=nil{t.Fatal(e)}
 epoch:=strings.Repeat("a",64)
 hs,e:=winReserveScattering(dir,epoch);if e!=nil{t.Fatal(e)}
 if e=os.Rename(filepath.Join(dir,"queue"),filepath.Join(dir,"other"));e==nil{winClose(hs);t.Fatal("queue moved")}
 winClose(hs)
 if hs,e=winReserveScattering(dir,epoch);e==nil{winClose(hs);t.Fatal("epoch reused")}
 if e=os.WriteFile(filepath.Join(dir,"queue","fixture.ready"),[]byte("opaque"),0600);e!=nil{t.Fatal(e)}
 if hs,e=winReserveScattering(dir,strings.Repeat("b",64));e==nil{winClose(hs);t.Fatal("nonempty queue accepted")}
}
