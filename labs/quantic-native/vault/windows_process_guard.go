//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -ladvapi32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wchar.h>

// Restrict NEW process handles. The creator's already-held handle and
// privileged SYSTEM/debug access are outside this discretionary boundary.
static DWORD qv_process_dacl(void) {
 HANDLE token=NULL;
 DWORD len=0,rc=ERROR_ACCESS_DENIED;
 PTOKEN_USER user=NULL;
 LPWSTR sid=NULL;
 PSECURITY_DESCRIPTOR sd=NULL;
 PACL acl=NULL;
 BOOL present=FALSE,defaulted=FALSE;
 WCHAR text[512];
 if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))goto done;
 GetTokenInformation(token,TokenUser,NULL,0,&len);
 if(!len||len>65536)goto done;
 user=(PTOKEN_USER)LocalAlloc(LPTR,len);
 if(!user||!GetTokenInformation(token,TokenUser,user,len,&len))goto done;
 if(!ConvertSidToStringSidW(user->User.Sid,&sid)||wcslen(sid)>180)goto done;
 // 0x00101001 = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION |
 // PROCESS_TERMINATE. OWNER RIGHTS suppresses implicit WRITE_DAC.
 wcscpy(text,L"D:P(A;;GA;;;SY)(A;;0x00101001;;;OW)(A;;0x00101001;;;");
 wcscat(text,sid);wcscat(text,L")");
 if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(text,SDDL_REVISION_1,&sd,NULL))goto done;
 if(!GetSecurityDescriptorDacl(sd,&present,&acl,&defaulted)||!present||!acl)goto done;
 rc=SetSecurityInfo(GetCurrentProcess(),SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,NULL,NULL,acl,NULL);
done:
 if(sd)LocalFree(sd);
 if(sid)LocalFree(sid);
 if(user)LocalFree(user);
 if(token)CloseHandle(token);
 return rc;
}
*/
import "C"
import "fmt"

func winProtectCryptoProcess()error{
 if code:=C.qv_process_dacl();code!=0{return fmt.Errorf("native process access restriction refused (%d)",uint32(code))}
 return nil
}
