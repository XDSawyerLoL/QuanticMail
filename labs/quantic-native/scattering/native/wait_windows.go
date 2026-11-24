//go:build windows

package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var k32 = syscall.NewLazyDLL("kernel32.dll")
var createTimer = k32.NewProc("CreateWaitableTimerExW")
var setTimer = k32.NewProc("SetWaitableTimer")
var waitObject = k32.NewProc("WaitForSingleObject")
var closeHandle = k32.NewProc("CloseHandle")
var currentThread = k32.NewProc("GetCurrentThread")
var setPriority = k32.NewProc("SetThreadPriority")

// CREATE_WAITABLE_TIMER_HIGH_RESOLUTION (Windows 10 v1803+).
// Fail explicitly if not supported; no silent ordinary-timer substitution.
type nativeClock struct{ handle uintptr }

func newNativeClock() (*nativeClock, error) {
	h, _, e := createTimer.Call(0, 0, 2, 0x001F0003)
	if h == 0 {
		return nil, fmt.Errorf("CreateWaitableTimerExW high resolution: %v", e)
	}
	return &nativeClock{h}, nil
}
func (c *nativeClock) close() { closeHandle.Call(c.handle) }
func (c *nativeClock) wait(due time.Time) error {
	remaining := time.Until(due)
	if remaining <= 0 {
		return nil
	}
	// negative relative interval in 100-ns units; deadline recomputed each slot.
	ticks := -int64((remaining.Nanoseconds() + 99) / 100)
	r, _, e := setTimer.Call(c.handle, uintptr(unsafe.Pointer(&ticks)), 0, 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("SetWaitableTimer: %v", e)
	}
	r, _, e = waitObject.Call(c.handle, 0xffffffff)
	if r != 0 {
		return fmt.Errorf("WaitForSingleObject: %v / %d", e, r)
	}
	return nil
}
func setPacerPriority() error {
	h, _, _ := currentThread.Call()
	r, _, e := setPriority.Call(h, 1)
	if r == 0 {
		return fmt.Errorf("SetThreadPriority: %v", e)
	}
	return nil
}
