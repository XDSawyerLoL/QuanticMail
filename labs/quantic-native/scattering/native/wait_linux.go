//go:build linux

package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// CLOCK_MONOTONIC absolute deadlines: no accumulating relative-sleep drift.
// Go's time.Time retains a monotonic reference. Map it once to kernel time.
type nativeClock struct {
	origin time.Time
	base   int64
}

func newNativeClock() (*nativeClock, error) {
	origin := time.Now()
	var ts syscall.Timespec
	_, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	if e != 0 {
		return nil, e
	}
	return &nativeClock{origin, ts.Nano()}, nil
}
func (c *nativeClock) close() {}
func (c *nativeClock) wait(due time.Time) error {
	ts := syscall.NsecToTimespec(c.base + due.Sub(c.origin).Nanoseconds())
	for {
		_, _, e := syscall.Syscall6(syscall.SYS_CLOCK_NANOSLEEP, 1, 1, uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
		if e == 0 {
			return nil
		}
		if e != syscall.EINTR {
			return fmt.Errorf("clock_nanosleep: %w", e)
		}
	}
}
func setPacerPriority() error {
	return fmt.Errorf("priorité élevée Linux non activée automatiquement; utiliser une réservation administrée")
}
