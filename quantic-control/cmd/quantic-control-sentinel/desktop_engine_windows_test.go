//go:build windows

package main

import (
 "strings"
 "testing"
)

func TestDesktopInstallRequest(t *testing.T){
 ok:=`{"root":"C:\\watch","backups":["C:\\one.bak","C:\\two.zip"]}`
 r,err:=decodeDesktopInstall(strings.NewReader(ok))
 if err!=nil||len(r.Backups)!=2{t.Fatal("valid input refused",err)}
 for _,bad:=range []string{
  "{}",
  ok+" {}",
  strings.Replace(ok,"two.zip","ONE.BAK",1),
  strings.Replace(ok,"root","unknown",1),
  strings.Repeat("x",65537),
 }{
  if _,err:=decodeDesktopInstall(strings.NewReader(bad));err==nil{t.Fatal("invalid request accepted")}
 }
}
