//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -lwtsapi32 -luser32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wtsapi32.h>
#include <stdio.h>

// Poll only the current interactive session. A disconnect, lock, failed
// query or suspend is a terminal invalidation; unlock never revives it.
static int qv_interactive_unlocked(void) {
 DWORD sid=0, size=0;
 LPWSTR buffer=NULL;
 if(!ProcessIdToSessionId(GetCurrentProcessId(),&sid)||sid==0) return 0;
 if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,sid,WTSSessionInfoEx,&buffer,&size)) return 0;
 int ok=0;
 if(size>=sizeof(WTSINFOEXW)){
  WTSINFOEXW *info=(WTSINFOEXW*)buffer;
  if(info->Level==1){
   WTSINFOEX_LEVEL1_W *s=&info->Data.WTSInfoExLevel1;
   ok=(s->SessionId==sid && s->SessionState==WTSActive && s->SessionFlags==WTS_SESSIONSTATE_UNLOCK);
  }
 }
 WTSFreeMemory(buffer);
 return ok;
}
static LRESULT CALLBACK qv_session_proc(HWND h,UINT m,WPARAM w,LPARAM l){
 if(m==WM_WTSSESSION_CHANGE){
  if(w==WTS_SESSION_LOCK || w==WTS_SESSION_LOGOFF || w==WTS_CONSOLE_DISCONNECT || w==WTS_REMOTE_DISCONNECT || w==WTS_SESSION_REMOTE_CONTROL){
   PostQuitMessage(0);return 0;
  }
 }
 if(m==WM_POWERBROADCAST && (w==PBT_APMSUSPEND || w==PBT_APMRESUMEAUTOMATIC)){PostQuitMessage(0);return TRUE;}
 if(m==WM_ENDSESSION || m==WM_CLOSE){PostQuitMessage(0);return 0;}
 if(m==WM_TIMER){
  DWORD available=0;
  HANDLE input=GetStdHandle(STD_INPUT_HANDLE);
  if(!PeekNamedPipe(input,NULL,0,NULL,&available,NULL)||available!=0||!qv_interactive_unlocked()){PostQuitMessage(0);}
  else {fputs("ALIVE\n",stdout);fflush(stdout);}
  return 0;
 }
 return DefWindowProcW(h,m,w,l);
}
static int qv_watch_session(void){
 HINSTANCE inst=GetModuleHandleW(NULL);
 WNDCLASSW cls={0};
 cls.lpfnWndProc=qv_session_proc;cls.hInstance=inst;cls.lpszClassName=L"QuanticSillageSessionWatchLab";
 if(!RegisterClassW(&cls))return 0;
 HWND h=CreateWindowExW(0,cls.lpszClassName,L"",WS_POPUP,0,0,0,0,NULL,NULL,inst,NULL);
 if(!h)return 0;
 if(!WTSRegisterSessionNotification(h,NOTIFY_FOR_THIS_SESSION)){DestroyWindow(h);return 0;}
 if(!qv_interactive_unlocked()||!SetTimer(h,1,500,NULL)){
  WTSUnRegisterSessionNotification(h);DestroyWindow(h);return 0;
 }
 fputs("READY\n",stdout);fflush(stdout);
 MSG msg;
 while(GetMessageW(&msg,NULL,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
 KillTimer(h,1);WTSUnRegisterSessionNotification(h);DestroyWindow(h);
 fputs("LOCKED\n",stdout);fflush(stdout);
 return 1;
}
*/
import "C"
import "runtime"

func winWatchSessionCLI(args []string)error{
 if len(args)!=2{return portableRefusal}
 runtime.LockOSThread()
 defer runtime.UnlockOSThread()
 if C.qv_watch_session()==0{return portableRefusal}
 return nil
}
