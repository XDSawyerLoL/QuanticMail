//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -lcredui -luser32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincred.h>
static int qv_gui_approve(void) {
 return MessageBoxW(NULL,L"Creer un nouveau coffre de TEST local ? Aucun compte reel ne sera modifie.",
  L"Quantic Sillage - Identity Vault",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2|MB_SETFOREGROUND)==IDYES;
}
static int qv_gui_secret(const WCHAR *prompt,WCHAR *password,DWORD capacity) {
 WCHAR user[CREDUI_MAX_USERNAME_LENGTH+1]=L"Quantic Sillage";
 CREDUI_INFOW ui={0};
 ui.cbSize=sizeof(ui);
 ui.pszCaptionText=L"Quantic Sillage - coffre de test";
 ui.pszMessageText=prompt;
 BOOL save=FALSE;
 DWORD result=CredUIPromptForCredentialsW(&ui,L"QuanticSillage.LocalSyntheticVault",
  NULL,0,user,CREDUI_MAX_USERNAME_LENGTH+1,password,capacity,&save,
  CREDUI_FLAGS_GENERIC_CREDENTIALS|CREDUI_FLAGS_ALWAYS_SHOW_UI|
  CREDUI_FLAGS_DO_NOT_PERSIST|CREDUI_FLAGS_EXCLUDE_CERTIFICATES|
  CREDUI_FLAGS_KEEP_USERNAME);
 SecureZeroMemory(user,sizeof(user));
 return result==NO_ERROR && !save;
}
*/
import "C"

import (
 "errors"
 "encoding/json"
 "os"
 "path/filepath"
 "unsafe"
)

// No secret goes through PowerShell, process arguments, files or redirected IO.
func winGUISecret(prompt string)([]byte,error){
 var buf [257]uint16
 defer clear(buf[:])
 if C.qv_gui_secret(winWide(prompt),(*C.WCHAR)(unsafe.Pointer(&buf[0])),C.DWORD(len(buf)))==0{
  return nil,errors.New("graphical secret entry cancelled or refused")
 }
 return winGUISecretBytes(buf[:])
}
func winGUISecretBytes(buf []uint16)([]byte,error){
 end:=0
 for end<len(buf)&&buf[end]!=0{end++}
 if end<20||end>256||end==len(buf){return nil,portableRefusal}
 out:=make([]byte,end)
 for i,c:=range buf[:end]{
  if c<32||c>126{clear(out);return nil,portableRefusal}
  out[i]=byte(c)
 }
 return out,nil
}
func winGUIConfirmSecret(prompt string)([]byte,error){
 p,e:=winGUISecret(prompt);if e!=nil{return nil,e}
 q,e:=winGUISecret("Confirmer exactement la phrase precedente (20 caracteres minimum).")
 if e!=nil{clear(p);return nil,e};defer clear(q)
 if !validPortablePassword(p)||!equalSecret(p,q){clear(p);return nil,portableRefusal}
 return p,nil
}
func winGUIProvision(dir,quorum,addr string)(map[string]string,error){
 // Refuse invalid parameters and existing target before asking for secrets.
 if !hashRE.MatchString(quorum)||!strongAddr.MatchString(addr){return nil,portableRefusal}
 if _,_,e:=winPathParts(dir);e!=nil{return nil,e}
 if _,e:=os.Lstat(dir);!os.IsNotExist(e){return nil,windowsStorageRefusal}
 if !winGUIApprove(){return nil,portableRefusal}
 pw,e:=winGUIConfirmSecret("Choisir une phrase secrete classique (20 a 256 caracteres ASCII).")
 if e!=nil{return nil,e};defer clear(pw)
 pq,e:=winGUIConfirmSecret("Choisir une phrase post-quantique DIFFERENTE (20 a 256 caracteres ASCII).")
 if e!=nil{return nil,e};defer clear(pq)
 if equalSecret(pw,pq){return nil,portableRefusal}
 return winGUIProvisionAndVerify(dir,quorum,addr,pw,pq)
}
func winGUIApprove()bool{return C.qv_gui_approve()!=0}

// No successful GUI creation is reported until both encrypted stores have
// been independently reopened and their public bindings verified. The local
// identity record is public metadata, not an external trust anchor.
func winGUIProvisionAndVerify(dir,quorum,addr string,pw,pq []byte)(map[string]string,error){
 result,e:=winProvisionAutoController(dir,quorum,addr,pw,pq)
 if e!=nil{return nil,e}
 if e=winGUIVerifyStored(dir,quorum,result,pw,pq);e!=nil{return nil,e}
 result["quorumPin"]=quorum
 result["localReadback"]="verified"
 data,e:=json.Marshal(result);if e!=nil{return nil,e}
 if e=winWritePrivate(filepath.Join(dir,"identity-public.json"),data);e!=nil{return nil,e}
 return result,nil
}
func winGUIVerifyStored(dir,quorum string,r map[string]string,pw,pq []byte)error{
 pub,e:=appPublic(r["controllerPublic"]);if e!=nil{return e}
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+quorum+"\x00",pw,r["signingPin"],r["encryptionPin"])
 if e!=nil{return e}
 point:=k.agreement.PublicKey().Bytes()
 device:="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(point[1:33])+":"+b64.EncodeToString(point[33:])))[:32]
 if device!=r["deviceId"]{return portableRefusal}
 binding,e:=pqBinding(r["signingPin"],r["encryptionPin"],hexHash(pub),quorum,r["address"],device);if e!=nil{return e}
 p,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pq,r["address"],device,r["kemPin"],r["dsaPin"])
 if e!=nil{return e}
 p.close()
 return nil
}
