// Quantic Scattering V7.0: native, keyless, JVM-independent UDP constant-rate pacer.
// This is a research tool, not a real-time or anonymity guarantee.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	packetSize = 168
	maxFrames  = 30000
	magic      = "QS69Q001"
	headerSize = 16
	digestSize = 32
)

var ingested atomic.Uint64
var readyPipe bool

type Config struct {
	Target, QueueDir, Report, Slots string
	PeriodUs                        int
	KernelInterface                 string
	Horizon                         time.Duration
	WaitMode                        string
	Elevated                        bool
	Duration                        time.Duration
	Poll                            time.Duration
}
type Stats struct {
	Planned, Sent, Missed, Errors uint64
	MaxLateUs                     int64
	CoverStarved, SpacingSkipped  uint64
	Times                         []int64
	Duration                      time.Duration
}

func readBundle(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < headerSize+digestSize || info.Size() > headerSize+maxFrames*packetSize+digestSize {
		return nil, fmt.Errorf("taille hors bornes")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(headerSize+maxFrames*packetSize+digestSize+1)))
	if err != nil {
		return nil, err
	}
	if len(data) < headerSize+digestSize || string(data[:8]) != magic {
		return nil, errors.New("en-tete invalide")
	}
	count := int(binary.BigEndian.Uint32(data[8:12]))
	frameSize := int(binary.BigEndian.Uint32(data[12:16]))
	if count < 1 || count > maxFrames || frameSize != packetSize || len(data) != headerSize+count*packetSize+digestSize {
		return nil, errors.New("dimensions invalides")
	}
	calc := sha256.Sum256(data[:len(data)-digestSize])
	if !equalConstantTime(calc[:], data[len(data)-digestSize:]) {
		return nil, errors.New("SHA256 incorrect")
	}
	out := make([][]byte, count)
	for i := range out {
		start := headerSize + i*packetSize
		out[i] = data[start : start+packetSize]
	}
	return out, nil
}
func equalConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	v := byte(0)
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
func loadQueue(path string, queue chan<- []byte, stop <-chan struct{}, poll time.Duration) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		entries, err := os.ReadDir(path)
		if err == nil {
			names := make([]string, 0)
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".ready") {
					names = append(names, e.Name())
				}
			}
			sort.Strings(names)
			for _, name := range names {
				original := filepath.Join(path, name)
				claimed := strings.TrimSuffix(original, ".ready") + ".working"
				if err := os.Rename(original, claimed); err != nil {
					continue
				}
				frames, err := readBundle(claimed)
				if err != nil {
					os.Rename(claimed, strings.TrimSuffix(claimed, ".working")+".invalid")
					fmt.Fprintf(os.Stderr, "REJET de lot: %s: %v\n", name, err)
					continue
				}
				for _, frame := range frames {
					select {
					case queue <- frame:
					case <-stop:
						return
					}
				}
				ingested.Add(uint64(len(frames)))
				// A queued packet is volatile. On a hard crash, delivery isn't assured.
				_ = os.Rename(claimed, strings.TrimSuffix(claimed, ".working")+".loaded")
			}
		}
		select {
		case <-ticker.C:
		case <-stop:
			return
		}
	}
}
func coverWorker(out chan<- []byte, stop <-chan struct{}) {
	for {
		v := make([]byte, packetSize)
		if _, err := rand.Read(v); err != nil {
			fmt.Fprintln(os.Stderr, "CSPRNG failure", err)
			return
		}
		select {
		case out <- v:
		case <-stop:
			return
		}
	}
}
func waitUntil(due time.Time) {
	for {
		remaining := time.Until(due)
		if remaining <= 0 {
			return
		}
		if remaining > 2*time.Millisecond {
			time.Sleep(remaining - 1000*time.Microsecond)
		} else { /* bounded active wait: not real-time */
		}
	}
}
func loop(c Config) (Stats, error) {
	var out Stats
	if c.PeriodUs < 1500 || c.PeriodUs > 1_000_000 {
		return out, errors.New("period-us doit être compris entre 1500 et 1000000")
	}
	if c.Poll < 10*time.Millisecond {
		return out, errors.New("poll trop rapide")
	}
	if c.Duration == 0 && c.Slots != "" {
		return out, errors.New("slot-csv illimité interdit : mémoire non bornée")
	}
	if err := os.MkdirAll(c.QueueDir, 0700); err != nil {
		return out, err
	}
	dest, err := net.ResolveUDPAddr("udp", c.Target)
	if err != nil {
		return out, err
	}
	if c.WaitMode == "kernel-fq" {
		if err := kernelPreflight(c, dest); err != nil {
			return out, err
		}
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	if c.WaitMode == "kernel-fq" {
		if err := kernelConfigure(conn); err != nil {
			return out, err
		}
	}
	_ = conn.SetWriteBuffer(1024 * 1024)
	queue := make(chan []byte, maxFrames)
	covers := make(chan []byte, 4096)
	stop := make(chan struct{})
	defer close(stop)
	// Buffer enough cover before pacing starts; no Java or prepared messages required.
	for i := 0; i < 1024; i++ {
		b := make([]byte, packetSize)
		if _, err = rand.Read(b); err != nil {
			return out, err
		}
		covers <- b
	}
	go coverWorker(covers, stop)
	go loadQueue(c.QueueDir, queue, stop, c.Poll)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if c.WaitMode == "kernel-fq" {
		return kernelLoop(c, conn, dest, queue, covers)
	}
	if c.WaitMode != "native" && c.WaitMode != "legacy" {
		return out, errors.New("wait-mode invalide")
	}
	var clock *nativeClock
	if c.WaitMode == "native" {
		clock, err = newNativeClock()
		if err != nil {
			return out, err
		}
		defer clock.close()
	}
	if c.Elevated {
		if err = setPacerPriority(); err != nil {
			return out, err
		}
	}
	if readyPipe { fmt.Println("READY") }
	period := time.Duration(c.PeriodUs) * time.Microsecond
	now := time.Now()
	anchor := now.Add(250 * time.Millisecond)
	limit := uint64(0)
	if c.Duration > 0 {
		limit = uint64(c.Duration / period)
		if limit < 1 {
			return out, errors.New("durée inférieure à une période")
		}
	}
	if c.Slots != "" {
		out.Times = make([]int64, 0, 8192)
	}
	var lastSend time.Time
	for slot := uint64(0); limit == 0 || slot < limit; slot++ {
		deadline := anchor.Add(time.Duration(slot) * period)
		if clock != nil {
			if err = clock.wait(deadline); err != nil {
				return out, err
			}
		} else {
			waitUntil(deadline)
		}
		late := time.Since(deadline)
		us := late.Microseconds()
		if us < 0 {
			us = 0
		}
		if us > out.MaxLateUs {
			out.MaxLateUs = us
		}
		out.Planned++
		if c.Slots != "" {
			out.Times = append(out.Times, us)
		}
		if late > period*3/4 {
			out.Missed++
			continue
		}
		// Never compress a catch-up burst, even if previous slot was late.
		if !lastSend.IsZero() && time.Since(lastSend) < period/2 {
			out.Missed++
			out.SpacingSkipped++
			continue
		}
		// Consume cover regardless of whether the queue contains sealed payload.
		// If cover generation is starved, use the same policy even with payload queued.
		var packet []byte
		select {
		case packet = <-covers:
		default:
			out.Missed++
			out.CoverStarved++
			continue
		}
		select {
		case packet = <-queue:
		default:
		}
		lastSend = time.Now()
		// Always one packet of constant length, regardless of application state.
		_, err = conn.WriteToUDP(packet, dest)
		if err != nil {
			out.Errors++
		} else {
			out.Sent++
		}
	}
	out.Duration = time.Since(now)
	return out, nil
}

// Continuous keyless UDP ingress. Keeps the destination network port open even
// when the Java consumer is absent. Never replies to the remote sender.
func sinkLoop(listen, forward string, duration time.Duration) (string, error) {
	dest, err := net.ResolveUDPAddr("udp4", forward)
	if err != nil {
		return "", err
	}
	if dest.IP.To4() == nil || !dest.IP.IsLoopback() {
		return "", errors.New("forward doit pointer vers 127.0.0.1:PORT")
	}
	listenAddr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return "", err
	}
	incoming, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return "", err
	}
	defer incoming.Close()
	_ = incoming.SetReadBuffer(1024 * 1024)
	local, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return "", err
	}
	defer local.Close()
	if readyPipe { fmt.Println("READY") }
	started := time.Now()
	received, forwarded, invalid, errorsCount := 0, 0, 0, 0
	buf := make([]byte, 2048)
	for duration == 0 || time.Since(started) < duration {
		_ = incoming.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := incoming.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			errorsCount++
			continue
		}
		received++
		if n != packetSize {
			invalid++
			continue
		}
		if _, err := local.WriteToUDP(buf[:n], dest); err != nil {
			errorsCount++
		} else {
			forwarded++
		}
	}
	return fmt.Sprintf("QS V7.1 NATIVE SINK | received=%d forwarded_local=%d malformed=%d local_errors=%d elapsed_ms=%d\n", received, forwarded, invalid, errorsCount, time.Since(started).Milliseconds()), nil
}
func main() {
	var c Config
	var mode, listen, forward string
	flag.StringVar(&mode, "mode", "send", "send (continuous cover + payload) or sink (always-on receiving endpoint)")
	flag.StringVar(&listen, "listen", ":49001", "sink UDP listen address")
	flag.StringVar(&forward, "forward", "127.0.0.1:49002", "sink local Java receiver address, must be loopback")
	flag.StringVar(&c.Target, "target", "127.0.0.1:49001", "UDP target; same destination for cover and payload")
	flag.StringVar(&c.QueueDir, "queue-dir", "queue", "private directory for QS69 pre-sealed .ready files")
	flag.StringVar(&c.Report, "report", "", "optional summary report; do not write in pacing loop")
	flag.StringVar(&c.Slots, "slot-csv", "", "optional private lateness CSV")
	flag.IntVar(&c.PeriodUs, "period-us", 20000, "fixed cadence in microseconds (default 20ms)")
	flag.DurationVar(&c.Duration, "duration", 0, "0 means run indefinitely, independent of JVM")
	flag.DurationVar(&c.Poll, "poll", 150*time.Millisecond, "queue polling interval")
	flag.StringVar(&c.WaitMode, "wait-mode", "native", "native timer, legacy busy-wait or Linux kernel-fq (experimental)")
	flag.StringVar(&c.KernelInterface, "kernel-interface", "", "explicit Linux interface with root fq, experimental")
	flag.DurationVar(&c.Horizon, "horizon", time.Second, "kernel-fq prequeue horizon; 100ms to 2s")
	flag.BoolVar(&c.Elevated, "above-normal", false, "opt-in Windows above-normal pacing thread priority; not real-time")
	flag.BoolVar(&readyPipe,"parent-pipe",false,"managed mode: READY on stdout; exit on parent stdin EOF or input")
	flag.Parse()
	if readyPipe { go func(){ var b [1]byte; _,_ = os.Stdin.Read(b[:]); os.Exit(0) }() }
	if mode == "sink" {
		out, err := sinkLoop(listen, forward, c.Duration)
		if err != nil {
			fmt.Fprintln(os.Stderr, "SINK ERROR:", err)
			os.Exit(2)
		}
		fmt.Print(out)
		return
	}
	if mode != "send" {
		fmt.Fprintln(os.Stderr, "mode invalide")
		os.Exit(2)
	}
	stats, err := loop(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
	pct := float64(100) * float64(stats.Missed) / float64(stats.Planned)
	if c.WaitMode == "kernel-fq" {
		fmt.Println("ATTENTION: sent=accepted by socket, missed=not queued; not wire delivery")
	}
	summary := fmt.Sprintf("QS V7.1 NATIVE | planned=%d sent=%d missed=%d (%.4f%%) write_errors=%d max_late_us=%d elapsed_ms=%d spacing_skipped=%d cover_starved=%d wait=%s SLA_1PCT=%v\n", stats.Planned, stats.Sent, stats.Missed, pct, stats.Errors, stats.MaxLateUs, stats.Duration.Milliseconds(), stats.SpacingSkipped, stats.CoverStarved, c.WaitMode, stats.Missed*100 <= stats.Planned && stats.Errors == 0)
	if c.WaitMode == "kernel-fq" {
		summary = strings.Replace(summary, "SLA_1PCT=", "ENQUEUE_1PCT=", 1)
	}
	fmt.Print(summary)
	if c.Report != "" {
		if e := os.WriteFile(c.Report, []byte(summary), 0600); e != nil {
			fmt.Fprintln(os.Stderr, e)
		}
	}
	if c.Slots != "" {
		f, e := os.OpenFile(c.Slots, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return
		}
		defer f.Close()
		w := csv.NewWriter(f)
		w.Write([]string{"slot", "lateness_us"})
		for i, x := range stats.Times {
			w.Write([]string{strconv.Itoa(i), strconv.FormatInt(x, 10)})
		}
		w.Flush()
	}
}
