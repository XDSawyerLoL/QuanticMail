//go:build windows

package main

import(
 "context"
 "io"
 "os"
 "strings"
 "syscall"
 "unsafe"

 "github.com/XDSawyerLoL/QuanticMail/quantic-control/vaultsession"
)

var enrollmentEdit,vaultHistoryButton uintptr
var vaultHistoryCancel context.CancelFunc
var vaultHistoryBusy bool

func showVaultNotice(hwnd uintptr,msg string){
 messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16(msg))),uintptr(unsafe.Pointer(u16("Identity Vault — accès laboratoire"))),0x40)
}
func startVaultHistory(hwnd uintptr){
 if vaultHistoryBusy{return}
 if !vaultsession.GraphicalProviderAvailable(){
  showVaultNotice(hwnd,"Cette édition ne contient pas le fournisseur post-quantique natif. Aucune connexion n'est effectuée.")
  return
 }
 var buf [65]uint16
 n,_,_:=user32.NewProc("GetWindowTextW").Call(enrollmentEdit,uintptr(unsafe.Pointer(&buf[0])),uintptr(len(buf)))
 if n!=64{showVaultNotice(hwnd,"Saisissez l'empreinte SHA-256 de l'enrôlement fournie séparément par l'autorité de confiance.");return}
 pin:=strings.ToLower(syscall.UTF16ToString(buf[:]))
 path,ok:=chooseLocalFile(hwnd,"Enrôlement public (*.json)\x00*.json\x00\x00","Choisir un enrôlement public préalablement vérifié")
 if !ok{return}
 file,err:=os.Open(path)
 if err!=nil{showVaultNotice(hwnd,"Enrôlement indisponible.");return}
 raw,err:=io.ReadAll(io.LimitReader(file,16385));file.Close()
 if err!=nil{showVaultNotice(hwnd,"Lecture de l'enrôlement refusée.");return}
 config,err:=vaultsession.ParseTrustedEnrollment(raw,pin)
 if err!=nil{showVaultNotice(hwnd,"Enrôlement refusé : empreinte ou paramètres incorrects.");return}
 log,err:=auditPath()
 if err!=nil{showVaultNotice(hwnd,"Historique local indisponible.");return}
 prompt:="Autoriser une seule consultation de l'historique local Sentinel avec ce coffre ?\n\n"+config.Identity.Address+"\n\nUtilisez uniquement un enrôlement et un logiciel obtenus d'une source de confiance. Le coffre demandera ensuite ses propres approbations. Aucune action d'administration n'est autorisée."
 approved,_,_:=messageBox.Call(hwnd,uintptr(unsafe.Pointer(u16(prompt))),uintptr(unsafe.Pointer(u16("Identity Vault — consentement"))),0x134)
 if approved!=6{return}
 vaultHistoryBusy=true
 enableWindow.Call(vaultHistoryButton,0)
 setLabel(vaultHistoryButton,"Vérification en cours…")
 ctx,cancel:=context.WithCancel(context.Background())
 vaultHistoryCancel=cancel
 go func(){
  defer cancel()
  records,err:=vaultsession.ReadGraphicalVaultHistory(ctx,config,log,35)
  if ctx.Err()!=nil{return}
  if err!=nil{enqueue(hwnd,update{kind:"vault_history",description:"Accès refusé ou coffre indisponible. Aucun historique authentifié affiché."});return}
  enqueue(hwnd,update{kind:"vault_history",description:"Preuve Identity Vault vérifiée ; autorisation de lecture consommée.",records:records})
 }()
}
func finishVaultHistory(item update){
 vaultHistoryBusy=false
 vaultHistoryCancel=nil
 enableWindow.Call(vaultHistoryButton,1)
 setLabel(vaultHistoryButton,"Historique via Identity Vault")
 addLog(item.description)
 for _,r:=range item.records{
  addLog(r.Time.Local().Format("02/01 15:04:05")+" ["+r.Type+"] "+r.Message)
 }
}
