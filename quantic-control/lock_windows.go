//go:build windows

package control

import (
    "os"
    "syscall"
    "unsafe"
)

const lockfileExclusiveLock = 0x00000002
const lockfileFailImmediately = 0x00000001

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var lockFileEx = kernel32.NewProc("LockFileEx")
var unlockFileEx = kernel32.NewProc("UnlockFileEx")

func lockStateFile(f *os.File) error {
    ov := new(syscall.Overlapped)
    r, _, err := lockFileEx.Call(f.Fd(), uintptr(lockfileExclusiveLock|lockfileFailImmediately), 0, 1, 0, uintptr(unsafe.Pointer(ov)))
    if r == 0 { if err != syscall.Errno(0) { return err }; return syscall.EINVAL }
    return nil
}
func unlockStateFile(f *os.File) error {
    ov := new(syscall.Overlapped)
    r, _, err := unlockFileEx.Call(f.Fd(), 0, 0, 1, 0, uintptr(unsafe.Pointer(ov)))
    if r == 0 { if err != syscall.Errno(0) { return err }; return syscall.EINVAL }
    return nil
}
