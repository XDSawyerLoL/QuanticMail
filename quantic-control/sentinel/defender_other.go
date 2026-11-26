//go:build !windows

package sentinel

import "errors"

// Windows Defender's operational event log is not available on other OSes.
func ReadRecentCFA(limit int)([]DefenderCFAEvent,bool,error){
    return nil,false,errors.New("Microsoft Defender Event Log requires Windows")
}
