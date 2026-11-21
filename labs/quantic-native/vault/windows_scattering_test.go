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
 if other,err:=winReserveScattering(dir,strings.Repeat("c",64));err==nil{other.close();hs.close();t.Fatal("concurrent epoch")}
 if e=os.Rename(filepath.Join(dir,"queue"),filepath.Join(dir,"other"));e==nil{hs.close();t.Fatal("queue moved")}
 if e=os.Rename(dir,dir+"-moved");e==nil{hs.close();t.Fatal("transport root moved")}
 hs.close()
 if hs,e=winReserveScattering(dir,epoch);e==nil{hs.close();t.Fatal("epoch reused")}
 if e=os.WriteFile(filepath.Join(dir,"queue","fixture.ready"),[]byte("opaque"),0600);e!=nil{t.Fatal(e)}
 if hs,e=winReserveScattering(dir,strings.Repeat("b",64));e==nil{hs.close();t.Fatal("nonempty queue accepted")}
}
