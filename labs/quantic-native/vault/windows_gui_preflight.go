//go:build windows && cgo && pqopenssl

package main

import (
 "encoding/json"
 "os"
)

// A human-operated, local-only diagnostic for the actual Windows approval and
// Credential UI dialogs. It does NOT unlock, create or migrate any vault.
// Never accept a real password, credentials or configured identity in this test.
func winGUIPreflight(args []string) error {
 if len(args)!=2 || args[1]!="--gui-credential-preflight-lab" { return portableRefusal }
 if !winGUIApprove("Test des fenetres Windows uniquement. Aucun coffre n'est ouvert. Continuer ?") {
  return portableRefusal
 }
 secret,err:=winGUIPassphrase("DIAGNOSTIC : saisir ALPHA-TEST-ONLY. Aucun vrai mot de passe.",true)
 if err!=nil{return err}
 defer clear(secret)
 if !equalSecret(secret,[]byte("ALPHA-TEST-ONLY")) { return portableRefusal }
 // Only a constant, non-sensitive result may leave the native process.
 return json.NewEncoder(os.Stdout).Encode(struct {
  Status string `json:"status"`
  LabOnly bool `json:"labOnly"`
  VaultOpened bool `json:"vaultOpened"`
  NetworkUsed bool `json:"networkUsed"`
 }{Status:"windows-native-credential-dialogs-verified",LabOnly:true})
}
