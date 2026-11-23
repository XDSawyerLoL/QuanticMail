//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -lcredui -luser32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincred.h>

// Windows-owned protected credential entry. No clipboard API, command-line
// password, stdin echo, credential persistence or browser renderer.
static int qs_gui_secret(const WCHAR *prompt,WCHAR *result,DWORD cap,DWORD *written) {
 CREDUI_INFOW ui;
 ZeroMemory(&ui,sizeof(ui));
 ui.cbSize=sizeof(ui);
 ui.pszCaptionText=L"Quantic Sillage Alpha - Coffre natif";
 ui.pszMessageText=prompt;
 WCHAR username[CREDUI_MAX_USERNAME_LENGTH+1];
 WCHAR password[CREDUI_MAX_PASSWORD_LENGTH+1];
 ZeroMemory(username,sizeof(username));
 ZeroMemory(password,sizeof(password));
 lstrcpyW(username,L"Quantic Sillage");
 BOOL save=FALSE;
 DWORD code=CredUIPromptForCredentialsW(
  &ui,L"QuanticSillage-Alpha-Lab-LocalOnly",NULL,0,
  username,CREDUI_MAX_USERNAME_LENGTH+1,
  password,CREDUI_MAX_PASSWORD_LENGTH+1,&save,
  CREDUI_FLAGS_GENERIC_CREDENTIALS|CREDUI_FLAGS_ALWAYS_SHOW_UI|
  CREDUI_FLAGS_DO_NOT_PERSIST|CREDUI_FLAGS_KEEP_USERNAME);
 int ok=0;
 if(code==NO_ERROR && !save) {
  DWORD len=(DWORD)lstrlenW(password);
  if(len>0 && len+2<cap && len<=CREDUI_MAX_PASSWORD_LENGTH) {
    CopyMemory(result,password,len*sizeof(WCHAR));
    result[len]=L'\r';result[len+1]=L'\n';
    *written=len+2;ok=1;
  }
 }
 SecureZeroMemory(password,sizeof(password));
 SecureZeroMemory(username,sizeof(username));
 return ok;
}
static int qs_gui_confirm(const WCHAR *message) {
 int code=MessageBoxW(NULL,message,L"Quantic Sillage - Autorisation du coffre",
    MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2|MB_SETFOREGROUND|MB_TOPMOST);
 return code==IDYES;
}
*/
import "C"

import (
 "errors"
 "runtime"
 "strings"
 "unsafe"
)

// Only the specifically selected GUI broker may call these functions.
// The existing console broker stays unchanged until Windows UI acceptance tests.
func winGUISecret(prompt string,secret bool)([]byte,error){
 if !secret||len(prompt)<1||len(prompt)>192||strings.ContainsAny(prompt,"\r\n\x00"){
  return nil,portableRefusal
 }
 runtime.LockOSThread();defer runtime.UnlockOSThread()
 var buf [258]uint16;defer clear(buf[:])
 var n C.DWORD
 if C.qs_gui_secret(winWide(prompt),(*C.WCHAR)(unsafe.Pointer(&buf[0])),C.DWORD(len(buf)),&n)==0{
  return nil,errors.New("native password dialog cancelled or unavailable")
 }
 if n<3||n>258{return nil,portableRefusal}
 return winConsoleBytes(buf[:int(n)])
}
func winGUIApprove(detail string)bool{
 if len(detail)<1||len(detail)>1024||strings.ContainsAny(detail,"\r\n\x00"){return false}
 runtime.LockOSThread();defer runtime.UnlockOSThread()
 return C.qs_gui_confirm(winWide(detail))!=0
}
