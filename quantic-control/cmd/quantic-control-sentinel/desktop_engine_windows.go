//go:build windows

package main

import (
 "encoding/json"
 "errors"
 "io"
 "os"
 "strings"

 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

type desktopInstallRequest struct {
 Root string `json:"root"`
 Backups []string `json:"backups"`
}

func decodeDesktopInstall(r io.Reader)(desktopInstallRequest,error){
 var req desktopInstallRequest
 raw,err:=io.ReadAll(io.LimitReader(r,65537))
 if err!=nil||len(raw)==0||len(raw)>65536{return req,errors.New("invalid request size")}
 d:=json.NewDecoder(strings.NewReader(string(raw)));d.DisallowUnknownFields()
 if err:=d.Decode(&req);err!=nil{return req,err}
 var extra any
 if d.Decode(&extra)!=io.EOF{return req,errors.New("trailing input")}
 if req.Root==""||len(req.Root)>2048||len(req.Backups)<1||len(req.Backups)>sentinel.MaxBackupLocks{return req,errors.New("invalid selection")}
 for i,p:=range req.Backups{
  if p==""||len(p)>2048{return req,errors.New("invalid backup")}
  for _,q:=range req.Backups[:i]{if strings.EqualFold(p,q){return req,errors.New("duplicate backup")}}
 }
 return req,nil
}

// Invoked only after explicit confirmation in the unified desktop. No
// console, secrets, user paths in command-line arguments, or registry
// mutation except the existing voluntary resident installation.
func installFromDesktop(r io.Reader)error{
 req,err:=decodeDesktopInstall(r);if err!=nil{return err}
 if err:=validateSelectedRoot(req.Root);err!=nil{return err}
 var locks []*sentinel.BackupLock
 defer func(){for _,l:=range locks{_ =l.Close()}}()
 ids:=make([]sentinel.BackupIdentity,0,len(req.Backups))
 for _,p:=range req.Backups{
  l,err:=sentinel.LockBackup(p);if err!=nil{return err}
  locks=append(locks,l);ids=append(ids,l.Identity())
 }
 return installResident(req.Root,ids...)
}

func desktopCommand()bool{
 if len(os.Args)!=2{return false}
 switch os.Args[1]{
 case "--desktop-install":
  if installFromDesktop(os.Stdin)!=nil{os.Exit(2)}
  return true
 case "--desktop-uninstall":
  if uninstallResident()!=nil{os.Exit(2)}
  return true
 }
 return false
}
