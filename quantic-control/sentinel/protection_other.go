//go:build !windows

package sentinel
import("context";"errors")
func ReadProtectionSnapshot(ctx context.Context)(ProtectionSnapshot,error){
 return ProtectionSnapshot{},errors.New("Windows Defender unavailable")
}
