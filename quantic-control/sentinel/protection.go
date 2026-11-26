package sentinel

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "strings"
 "time"
)

// ProtectionSnapshot is a read-only report from the Windows Defender
// provider. It is a configuration observation, NOT a guarantee of prevention.
type ProtectionSnapshot struct {
 Mode *int `json:"mode"`
 Antivirus *bool `json:"antivirus"`
 RealTime *bool `json:"realtime"`
 RunningMode string `json:"running_mode"`
 DefaultFolders []string `json:"default_folders"`
 ExtraFolders []string `json:"extra_folders"`
 CheckedAt time.Time `json:"-"`
}
type ProtectionAssessment struct{
 State string
 Detail string
 FolderListed bool
}
func ParseProtectionSnapshot(raw []byte,now time.Time)(ProtectionSnapshot,error){
 if len(raw)==0||len(raw)>65536{return ProtectionSnapshot{},errors.New("invalid Defender report size")}
 var s ProtectionSnapshot
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var extra any
 if d.Decode(&s)!=nil||d.Decode(&extra)!=io.EOF||s.Mode==nil||s.Antivirus==nil||s.RealTime==nil||len(s.RunningMode)>64||len(s.DefaultFolders)+len(s.ExtraFolders)>1024{return ProtectionSnapshot{},errors.New("incomplete Defender provider report")}
 for _,list:=range [][]string{s.DefaultFolders,s.ExtraFolders}{
  for _,path:=range list{if len(path)>32767||strings.ContainsRune(path,0){return ProtectionSnapshot{},errors.New("invalid Defender folder")}}
 }
 s.CheckedAt=now
 return s,nil
}
// AssessProtection never describes an audit-only, disk-only, passive or
// unverified folder as covered by CFA. Folder matching is lexical only;
// aliases, junctions and reparse points are not validated by this check.
func AssessProtection(s ProtectionSnapshot,root string,now time.Time)ProtectionAssessment{
 a:=ProtectionAssessment{State:"unknown",Detail:"État de la protection Windows non vérifié."}
 if s.Mode==nil||s.Antivirus==nil||s.RealTime==nil||s.CheckedAt.IsZero()||now.Before(s.CheckedAt)||now.Sub(s.CheckedAt)>time.Minute{return a}
 switch *s.Mode{
 case 0:a.State="disabled";a.Detail="Accès contrôlé aux dossiers désactivé.";return a
 case 2:a.State="audit";a.Detail="Mode audit : les écritures ne sont pas bloquées par cette règle.";return a
 case 3,4:a.State="disk_only";a.Detail="Mode secteurs de disque uniquement : couverture des fichiers non confirmée.";return a
 case 1:
 default:a.Detail="Mode Defender inconnu.";return a
 }
 if !*s.Antivirus||!*s.RealTime||!strings.EqualFold(s.RunningMode,"Normal"){
  a.State="not_confirmed";a.Detail="Blocage configuré, mais antivirus actif et temps réel non confirmés.";return a
 }
 if root==""{a.State="configured";a.Detail="Blocage CFA configuré dans Defender. Sélectionnez un dossier pour vérifier sa présence.";return a}
 for _,list:=range [][]string{s.DefaultFolders,s.ExtraFolders}{
  for _,p:=range list{
   if withinMonitoredRoot(root,p){a.FolderListed=true;break}
  }
 }
 if a.FolderListed{a.State="configured_folder";a.Detail="Blocage Defender configuré ; dossier présent dans la liste (chemin déclaré)."}else{a.State="folder_unconfirmed";a.Detail="Blocage Defender configuré ; dossier sélectionné non confirmé dans la liste."}
 return a
}
