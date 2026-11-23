//go:build windows

package main

import (
 "strings"
 "testing"
)
func TestWindowsPowerShellAlwaysUsesSystemModules(t *testing.T){
 env:=childPowerShellEnv([]string{
  "SystemRoot=C:\\Windows",
  "PSModulePath=C:\\Untrusted\\Modules",
  "psmodulepath=C:\\Overridden\\Modules",
  "PSModuleAnalysisCachePath=C:\\Untrusted\\Cache",
  "PATH=C:\\Windows\\System32",
 },"C:\\Windows")
 count:=0
 for _,item:=range env{
  if strings.HasPrefix(strings.ToLower(item),"psmodulepath="){
   count++
   want:=`PSModulePath=C:\Windows\System32\WindowsPowerShell\v1.0\Modules`
   if item!=want{t.Fatalf("non-system PowerShell module source: %q",item)}
  }
  if strings.HasPrefix(strings.ToLower(item),"psmoduleanalysiscachepath="){
   t.Fatal("untrusted PowerShell module cache remained")
  }
 }
 if count!=1{t.Fatalf("expected one system module root, got %d",count)}
}
