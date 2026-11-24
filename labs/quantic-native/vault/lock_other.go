//go:build linux

package main

import (
	"os"
	"syscall"
)

func lockReplay(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
