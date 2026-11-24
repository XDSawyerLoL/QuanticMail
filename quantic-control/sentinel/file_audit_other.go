//go:build !windows

package sentinel

import "errors"

// Windows Security 4663 file-audit events are Windows-specific.
func ReadRecentFileAudits(limit int)([]FileAccessAudit,bool,error){
 return nil,false,errors.New("Windows Security 4663 requires Windows")
}
