//go:build windows && cgo && pqopenssl

package main

/*
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Open the actual local console, never the broker's redirected stdin/stdout.
// Refuse detached processes. Preserve the previous console input mode.
static int qv_console_read(const WCHAR *prompt, WCHAR *buf,DWORD cap,DWORD *n,int secret) {
 HANDLE in=CreateFileW(L"CONIN$",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
  NULL,OPEN_EXISTING,0,NULL);
 if(in==INVALID_HANDLE_VALUE)return 0;
 HANDLE out=CreateFileW(L"CONOUT$",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
  NULL,OPEN_EXISTING,0,NULL);
 if(out==INVALID_HANDLE_VALUE){CloseHandle(in);return 0;}
 DWORD old=0,mode=0,done=0;
 int ok=0,changed=0;
 if(!GetConsoleMode(in,&old)||!GetConsoleMode(out,&mode))goto end;
 mode=(old|ENABLE_LINE_INPUT|ENABLE_PROCESSED_INPUT)&~(ENABLE_VIRTUAL_TERMINAL_INPUT);
 if(secret)mode&=~ENABLE_ECHO_INPUT;else mode|=ENABLE_ECHO_INPUT;
 if(!SetConsoleMode(in,mode))goto end;
 changed=1;
 if(!FlushConsoleInputBuffer(in))goto end;
 if(!WriteConsoleW(out,prompt,lstrlenW(prompt),&done,NULL))goto end;
 if(!ReadConsoleW(in,buf,cap,n,NULL))goto end;
 if(*n<2||*n>=cap||buf[*n-2]!=L'\r'||buf[*n-1]!=L'\n')goto end;
 ok=1;
end:
 if(changed){
  FlushConsoleInputBuffer(in);
  if(!SetConsoleMode(in,old))ok=0;
 }
 if(secret)WriteConsoleW(out,L"\r\n",2,&done,NULL);
 CloseHandle(out);CloseHandle(in);return ok;
}
*/
import "C"

import (
 "errors"
 "unsafe"
)

// Restrict the laboratory to printable ASCII, preserving bytes exactly.
// No environment, command-line, clipboard, standard-input or file fallback.
func winConsoleLine(prompt string,secret bool)([]byte,error){
 var buf [1027]uint16
 defer clear(buf[:])
 var n C.DWORD
 flag:=C.int(0);if secret{flag=1}
 if C.qv_console_read(winWide(prompt),(*C.WCHAR)(unsafe.Pointer(&buf[0])),C.DWORD(len(buf)),&n,flag)==0{
  return nil,errors.New("interactive Windows console required")
 }
 return winConsoleBytes(buf[:int(n)])
}
func winConsoleBytes(line []uint16)([]byte,error){
 if len(line)<2||len(line)>1026||line[len(line)-2]!=13||line[len(line)-1]!=10{return nil,windowsStorageRefusal}
 out:=make([]byte,len(line)-2)
 for i,c:=range line[:len(line)-2]{
  if c<32||c>126{clear(out);return nil,windowsStorageRefusal};out[i]=byte(c)
 }
 return out,nil
}
func winConfirmSecret(prompt string)([]byte,error){
 p,e:=winConsoleLine(prompt,true);if e!=nil{return nil,e}
 q,e:=winConsoleLine("Confirm the laboratory passphrase: ",true)
 if e!=nil{clear(p);return nil,e};defer clear(q)
 if !validPortablePassword(p)||!equalSecret(p,q){clear(p);return nil,portableRefusal}
 return p,nil
}
func winApprove(prompt string)bool{
 a,e:=winConsoleLine(prompt+" Type APPROVE: ",false);if e!=nil{return false};defer clear(a)
 return equalSecret(a,[]byte("APPROVE"))
}
