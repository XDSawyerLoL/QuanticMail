//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func checkPortableDirectory(path string) error {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private directory required (0700)")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return errors.New("private directory owner mismatch")
	}
	return nil
}
func privatePortableFile(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && st.Nlink == 1
}
func syncPortableDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func ttyRead(prompt string, hide bool) ([]byte, error) {
	f, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return nil, errors.New("local controlling terminal required")
	}
	defer f.Close()
	if hide {
		var old syscall.Termios
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&old)))
		if errno != 0 {
			return nil, errno
		}
		next := old
		next.Lflag &^= syscall.ECHO
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&next)))
		if errno != 0 {
			return nil, errno
		}
		defer func() {
			syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
			fmt.Fprintln(f)
		}()
	}
	fmt.Fprint(f, prompt)
	r := bufio.NewReaderSize(f, 2048)
	b, e := r.ReadSlice('\n')
	if e != nil || len(b) > 1025 {
		return nil, errors.New("local input refused")
	}
	return append([]byte(nil), b[:len(b)-1]...), nil
}
func localSecret(prompt string) ([]byte, error) { return ttyRead(prompt, true) }
func localPortableApproval(prompt string) bool {
	b, e := ttyRead(prompt+" [taper OUI] : ", false)
	return e == nil && string(b) == "OUI"
}
