//go:build windows && cgo && pqopenssl

package main

import "testing"

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
