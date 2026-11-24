//go:build windows && cgo && pqopenssl

package main
import "testing"
func TestWindowsGUISecretBounds(t *testing.T){
 var good [257]uint16
 for i:=0;i<20;i++{good[i]='a'}
 p,e:=winGUISecretBytes(good[:]);if e!=nil||len(p)!=20{t.Fatal("valid phrase refused")};clear(p)
 for _,bad:=range []uint16{1,127,233}{
  modified:=good;modified[4]=bad
  if p,e:=winGUISecretBytes(modified[:]);e==nil{clear(p);t.Fatal("non printable ASCII accepted")}
 }
 if p,e:=winGUISecretBytes([]uint16{'a',0});e==nil{clear(p);t.Fatal("short secret accepted")}
 full:=make([]uint16,257);for i:=range full{full[i]='a'}
 if p,e:=winGUISecretBytes(full);e==nil{clear(p);t.Fatal("unterminated secret accepted")}
}
