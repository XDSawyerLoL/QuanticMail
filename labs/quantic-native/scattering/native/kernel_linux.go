//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

const soTxtime = 61

// Explicit preflight. FQ is not ETF: these are earliest departure times,
// not strict drop-if-late deadlines. No implicit modification of host qdiscs.
func verifyFQ(c Config, dest *net.UDPAddr, capacity int) error {
	if dest.IP.To4() == nil || c.KernelInterface == "" {
		return errors.New("kernel-fq requires IPv4 and --kernel-interface")
	}
	if c.Elevated || c.Slots != "" {
		return errors.New("kernel-fq: --above-normal and --slot-csv unsupported; use independent receiver")
	}
	raw, err := exec.Command("ip", "-j", "route", "get", dest.IP.String()).Output()
	if err != nil {
		return fmt.Errorf("route check: %w", err)
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if json.Unmarshal(raw, &routes) != nil || len(routes) != 1 || routes[0].Dev != c.KernelInterface {
		return errors.New("destination route does not use declared interface")
	}
	raw, err = exec.Command("tc", "-j", "qdisc", "show", "dev", c.KernelInterface).Output()
	if err != nil {
		return fmt.Errorf("qdisc check: %w", err)
	}
	var qs []struct {
		Kind    string `json:"kind"`
		Root    bool   `json:"root"`
		Options struct {
			Limit     int   `json:"limit"`
			FlowLimit int   `json:"flow_limit"`
			Horizon   int64 `json:"horizon"`
		} `json:"options"`
	}
	if json.Unmarshal(raw, &qs) != nil {
		return errors.New("unreadable qdisc configuration")
	}
	for _, q := range qs {
		if q.Root && q.Kind == "fq" && q.Options.Limit >= capacity && q.Options.FlowLimit >= capacity && q.Options.Horizon >= c.Horizon.Microseconds() {
			return nil
		}
	}
	return errors.New("root fq absent, or capacity/horizon insufficient; refusing to send")
}
func enableTxtime(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var op error
	// struct sock_txtime { clockid_t clockid; __u32 flags; } CLOCK_MONOTONIC, no deadline mode.
	val := [2]uint32{1, 0}
	err = raw.Control(func(fd uintptr) {
		_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, syscall.SOL_SOCKET, soTxtime, uintptr(unsafe.Pointer(&val[0])), 8, 0)
		if e != 0 {
			op = e
		}
	})
	if err != nil {
		return err
	}
	return op
}
func txtimeOOB(ns uint64) []byte {
	b := make([]byte, syscall.CmsgSpace(8))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = syscall.SOL_SOCKET
	h.Type = soTxtime
	h.SetLen(syscall.CmsgLen(8))
	binary.NativeEndian.PutUint64(b[syscall.CmsgLen(0):], ns)
	return b
}
func kernelPreflight(c Config, dest *net.UDPAddr) error {
	period := time.Duration(c.PeriodUs) * time.Microsecond
	if c.Horizon < 100*time.Millisecond || c.Horizon > 2*time.Second || c.Horizon < 4*period {
		return errors.New("invalid horizon: 100ms..2s and at least four periods")
	}
	if c.Duration > 0 && c.Duration < period {
		return errors.New("duration less than one period")
	}
	return verifyFQ(c, dest, int(c.Horizon/period)+8)
}
func kernelConfigure(conn *net.UDPConn) error { return enableTxtime(conn) }
func kernelLoop(c Config, conn *net.UDPConn, dest *net.UDPAddr, queue, covers <-chan []byte) (Stats, error) {
	var out Stats
	period := time.Duration(c.PeriodUs) * time.Microsecond
	clock, err := newNativeClock()
	if err != nil {
		return out, err
	}
	defer clock.close()
	started := time.Now()
	anchor := started.Add(c.Horizon)
	limit := uint64(0)
	if c.Duration > 0 {
		limit = uint64(c.Duration / period)
		if limit == 0 {
			return out, errors.New("duration less than one period")
		}
	}
	// Refill at a cadence independent of whether application packets are ready.
	// Only enqueue future slots, no user-space catch-up of expired slots.
	refill := c.Horizon / 4
	guard := period / 4
	if guard < time.Millisecond {
		guard = time.Millisecond
	}
	fmt.Printf("KERNEL_FQ anchor_mono_ns=%d period_ns=%d horizon_ns=%d\n", clock.base+anchor.Sub(clock.origin).Nanoseconds(), period.Nanoseconds(), c.Horizon.Nanoseconds())
	for slot := uint64(0); limit == 0 || slot < limit; {
		now := time.Now()
		until := now.Add(c.Horizon)
		for ; limit == 0 || slot < limit; slot++ {
			due := anchor.Add(time.Duration(slot) * period)
			if due.After(until) {
				break
			}
			out.Planned++
			if time.Until(due) <= guard {
				out.Missed++
				continue
			}
			var packet []byte
			select {
			case packet = <-covers:
			default:
				out.CoverStarved++
				out.Missed++
				continue
			}
			select {
			case packet = <-queue:
			default:
			}
			ns := clock.base + due.Sub(clock.origin).Nanoseconds()
			_, _, e := conn.WriteMsgUDP(packet, txtimeOOB(uint64(ns)), dest)
			if e != nil {
				out.Errors++
				return out, fmt.Errorf("scheduled enqueue failed: %w", e)
			}
			out.Sent++
		}
		if limit != 0 && slot >= limit {
			break
		}
		if err := clock.wait(now.Add(refill)); err != nil {
			return out, err
		}
	}
	// Keep the socket alive until the last scheduled time; do not confuse acceptance with delivery.
	if limit > 0 {
		if err := clock.wait(anchor.Add(time.Duration(limit) * period)); err != nil {
			return out, err
		}
	}
	out.Duration = time.Since(started)
	return out, nil
}
