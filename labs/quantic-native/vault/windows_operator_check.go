//go:build windows && cgo && pqopenssl

package main

import (
 "crypto/rand"
 "crypto/subtle"
 "encoding/hex"
 "encoding/json"
 "os"
)

// A local human-operated Win32 modal exercise. No real password, identity,
// stored key, relay or network activity. Unlike unit tests it must be run on
// the actual interactive desktop, and must never auto-approve anything.
func winGUIOperatorCheck(args []string)(bool,error){
 if len(args)<2||args[1]!="--windows-gui-operator-check-lab"{return false,nil}
 if len(args)!=2{return true,portableRefusal}
 if !winGUIApprove("TEST DE SECURITE (aucun compte reel). Cliquez OUI pour essayer les fenetres natives Windows. Sinon NON pour tout annuler."){return true,portableRefusal}
 var seed [8]byte
 if _,e:=rand.Read(seed[:]);e!=nil{return true,e}
 expected:=[]byte(hex.EncodeToString(seed[:]))
 defer clear(expected)
 // Do not display or echo a real vault passphrase. The randomly generated
 // code is short-lived and appears only in this native test dialog.
 got,e:=winGUISecret("TEST uniquement : recopiez le code temporaire "+string(expected)+" dans la zone masquee. Ne saisissez aucun vrai mot de passe.",true)
 if e!=nil{return true,e}
 match:=subtle.ConstantTimeCompare(got,expected)==1
 clear(got)
 if !match{return true,portableRefusal}
 if !winGUIApprove("TEST : cliquez OUI pour verifier une autorisation explicite. Le bouton NON doit rester selectionne par defaut."){return true,portableRefusal}
 if winGUIApprove("TEST DE REFUS : cliquez NON pour confirmer que le coffre respecte votre refus. Aucune operation ne sera effectuee."){return true,portableRefusal}
 return true,json.NewEncoder(os.Stdout).Encode(struct{
  Status string `json:"status"`
  LiveAccountUsed bool `json:"liveAccountUsed"`
  NetworkUsed bool `json:"networkUsed"`
  NativeUIVerified bool `json:"nativeUIVerified"`
  HumanInteractive bool `json:"humanInteractive"`
 }{Status:"native-windows-operator-check-passed",NativeUIVerified:true,HumanInteractive:true})
}
