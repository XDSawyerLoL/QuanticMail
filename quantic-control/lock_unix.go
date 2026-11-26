//go:build !windows

package control

import (
    "os"
    "syscall"
)

func lockStateFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlockStateFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
