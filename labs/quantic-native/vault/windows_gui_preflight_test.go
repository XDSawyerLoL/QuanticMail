//go:build windows && cgo && pqopenssl

package main

import "testing"

// Safe CI test: no actual modal dialog is launched on the runner.
// Real modal consent + CredUI password entry must be tested on a desktop.
func TestWindowsCredentialDiagnosticRefusal(t *testing.T) {
 for _,args:=range [][]string{
  {"Vault-PQ-lab.exe"},
  {"Vault-PQ-lab.exe","--unknown"},
  {"Vault-PQ-lab.exe","--gui-credential-preflight-lab","unexpected"},
 }{
  if err:=winGUIPreflight(args);err==nil{
   t.Fatalf("diagnostic accepted malformed arguments: %v",args)
  }
 }
}
