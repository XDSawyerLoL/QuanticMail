package vaultsession

import (
 "time"
 control "github.com/XDSawyerLoL/QuanticMail/quantic-control"
 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

// ReadAuthorizedAlerts is the local history handler. The path and record
// limit come from trusted local application configuration, not from the
// signed request. Authorization is consumed before reading any records.
// An unsuccessful read does not restore a spent authorization.
func(s *Session) ReadAuthorizedAlerts(r control.SignedRequest,localAuditPath string,limit int)([]sentinel.Record,error){
 if err:=s.AuthorizeRead(r,"alerts.read",time.Now());err!=nil{return nil,err}
 return sentinel.RecentRecords(localAuditPath,limit)
}
