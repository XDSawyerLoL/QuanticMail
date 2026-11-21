package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Laboratory journal. Trusted directory and OS account required. No protection
// against restoration of an older valid file or a malicious local administrator.
const replayCap = 16384
const replayHeader = "QV-REPLAY-LAB-V1\n"

type replayLog struct {
	f        *os.File
	seen     map[[32]byte]bool
	tail     [32]byte
	failed   bool
	anchor   checkpointAnchor
	anchorID string
	release func()
}

func replayBinding(sign, enc, app string) ([]byte, error) {
	if !hashRE.MatchString(sign) || !hashRE.MatchString(enc) || !hashRE.MatchString(app) {
		return nil, errors.New("invalid journal binding")
	}
	return []byte(replayHeader + sign + enc + app + "\n"), nil
}
func initReplay(path, sign, enc, app string) error {
	h, e := replayBinding(sign, enc, app)
	if e != nil {
		return e
	}
	if !filepath.IsAbs(path) {
		return errors.New("absolute journal path required")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(h); e != nil {
		return e
	}
	return f.Sync()
}
func openReplay(path, sign, enc, app string) (*replayLog, error) {
	h, e := replayBinding(sign, enc, app)
	if e != nil {
		return nil, e
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute journal path required")
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() {
		return nil, errors.New("journal missing or invalid")
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if e = lockReplay(f); e != nil {
		return nil, e
	}
	info2, e := f.Stat()
	if e != nil || !os.SameFile(info, info2) {
		return nil, errors.New("journal changed")
	}
	j, e := parseReplayHandle(f, h, info2.Size())
	if e != nil { return nil, e }
	ok = true
	return j, nil
}
// Caller must hold an exclusive, validated file handle at offset zero.
func parseReplayHandle(f *os.File,h []byte,size int64)(*replayLog,error) {
	n := size
	if n < int64(len(h)) || n > int64(len(h)+64*replayCap) || (n-int64(len(h)))%64 != 0 {
		return nil, errors.New("journal size invalid")
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(len(h)+64*replayCap+1)))
	if e != nil || int64(len(raw)) != n || string(raw[:len(h)]) != string(h) {
		return nil, errors.New("journal binding invalid")
	}
	j := &replayLog{f: f, seen: map[[32]byte]bool{}, tail: sha256.Sum256(h)}
	for i := len(h); i < len(raw); i += 64 {
		var k [32]byte
		copy(k[:], raw[i:i+32])
		next := hashRecord(j.tail, k)
		if j.seen[k] || string(next[:]) != string(raw[i+32:i+64]) {
			return nil, errors.New("journal damaged")
		}
		j.seen[k] = true
		j.tail = next
	}
	return j, nil
}
func hashRecord(prev, key [32]byte) [32]byte {
	var b [64]byte
	copy(b[:32], prev[:])
	copy(b[32:], key[:])
	return sha256.Sum256(b[:])
}
func (j *replayLog) has(k [32]byte) bool { return j.failed || j.seen[k] }
func (j *replayLog) consume(k [32]byte) error {
	if j.has(k) || len(j.seen) >= replayCap {
		return errors.New("replay or journal full")
	}
	next := hashRecord(j.tail, k)
	var b [64]byte
	copy(b[:32], k[:])
	copy(b[32:], next[:])
	n, e := j.f.Write(b[:])
	if e != nil || n != 64 {
		j.failed = true
		return errors.New("journal write failed")
	}
	if e = j.f.Sync(); e != nil {
		j.failed = true
		return e
	}
	// A result is released only after both the local fsync and remote CAS.
	// Any partial commit is intentionally fail-closed, including uncertain responses.
	if j.anchor != nil {
		if e = j.anchor.advance(j.anchorID, len(j.seen), j.tail, k); e != nil {
			j.failed = true
			return e
		}
	}
	j.seen[k] = true
	j.tail = next
	return nil
}
func (j *replayLog) close() { j.f.Close(); if j.release!=nil{j.release();j.release=nil} }
func replayID(domain string, data []byte) [32]byte {
	return sha256.Sum256(append([]byte(domain+"\x00"), data...))
}
func hexHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
