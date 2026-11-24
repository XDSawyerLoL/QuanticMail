//go:build windows && cgo && pqopenssl

package main

import (
 "testing"
 "strings"
 "path/filepath"
)

// The automated runner cannot honestly certify visible human interaction.
// The real test is the separate native GUI command executed by an operator.
func TestWindowsGUIOperatorCheckContract(t *testing.T){
 for _,args:=range [][]string{
  {"vault.exe"},
  {"vault.exe","--windows-gui-operator-check-lab","--silent"},
 }{
  ok,e:=winGUIOperatorCheck(args)
  if len(args)==1{
   if ok||e!=nil{t.Fatal("unexpected command accepted")}
  }else if !ok||e==nil{t.Fatal("extra arguments should be refused before UI")}
 }
}

func TestWindowsGUIProvisionRefusesInvalidTargetsBeforeDialog(t *testing.T){
 pin:=strings.Repeat("a",64)
 address:="alice~"+strings.Repeat("b",32)+"@quantic"
 existing:=t.TempDir()
 for _,args:=range [][]string{
  {"vault.exe","--provision-windows-controller-gui-lab"},
  {"vault.exe","--provision-windows-controller-gui-lab","relative",pin,address},
  {"vault.exe","--provision-windows-controller-gui-lab",existing,pin,address},
  {"vault.exe","--provision-windows-controller-gui-lab",filepath.Join(existing,"new"),"invalid",address},
 }{
  handled,e:=windowsVaultCLI(args)
  if !handled||e==nil{t.Fatal("invalid GUI provisioning must be refused")}
 }
}
