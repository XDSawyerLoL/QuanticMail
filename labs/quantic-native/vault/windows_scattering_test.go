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

func TestWindowsScatteringOverlapGuard(t *testing.T){
 root:=filepath.Join(t.TempDir(),"overlap")
 if e:=winCreateScattering(root);e!=nil{t.Fatal(e)}
 a,b,c:=filepath.Join(root,"lane-a"),filepath.Join(root,"lane-b"),filepath.Join(root,"lane-c")
 for _,p:=range []string{a,b,c}{if e:=winCreateScattering(p);e!=nil{t.Fatal(e)}}
 e1,e2:=strings.Repeat("a",64),strings.Repeat("b",64)
 g1,e:=winReserveScatteringOverlap(root,a,e1);if e!=nil{t.Fatal(e)}
 defer g1.close()
 if g,e:=winReserveScatteringOverlap(root,c,e1);e==nil{g.close();t.Fatal("cross-lane reuse")}
 g2,e:=winReserveScatteringOverlap(root,b,e2);if e!=nil{t.Fatal(e)}
 g2.close()
 if g,e:=winReserveScatteringOverlap(root,c,e2);e==nil{g.close();t.Fatal("cross-lane reuse after close")}
 if g,e:=winReserveScattering(root,e2);e==nil{g.close();t.Fatal("legacy reuse of shared epoch")}
 if e=os.Rename(root,root+"-moved");e==nil{t.Fatal("ledger moved during active lane")}
}
