package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// Pinned controller-key proof, not OS process identity. Only a trusted controller
// should hold the key. Fresh session nonce disallows cross-process frame replay.
type signedFrame struct {
	Seq  uint32 `json:"seq"`
	Body string `json:"body"`
	Sig  string `json:"sig"`
}

func appDigest(nonce []byte, seq uint32, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("quantic-vault-controller-lab/v1\x00"))
	h.Write(nonce)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], seq)
	h.Write(b[:])
	h.Write(body)
	var a [32]byte
	copy(a[:], h.Sum(nil))
	return a
}
func appPublic(raw string) (ed25519.PublicKey, error) {
	b, e := decode(raw, 32, 32)
	return ed25519.PublicKey(b), e
}
func authenticateFrames(pub ed25519.PublicKey, in io.Reader, out io.Writer, serve func(io.Reader, io.Writer) error) error {
 return authenticateFramesDelegated(pub,nil,in,out,serve)
}
func delegatedSessionDigest(nonce,ephemeral []byte)[]byte{
 h:=sha256.New();h.Write([]byte("quantic-native-controller-session-lab/v1\x00"));h.Write(nonce);h.Write(ephemeral);return h.Sum(nil)
}
func authenticateFramesDelegated(pub ed25519.PublicKey,controller ed25519.PrivateKey,in io.Reader,out io.Writer,serve func(io.Reader,io.Writer)error)error{
	nonce := make([]byte, 32)
	if _, e := rand.Read(nonce); e != nil {
		return e
	}
	hello:=map[string]string{"session":b64.EncodeToString(nonce)}
 if controller!=nil{hello["delegation"]=b64.EncodeToString(ed25519.Sign(controller,delegatedSessionDigest(nonce,pub)))}
 if e := json.NewEncoder(out).Encode(hello); e != nil {
		return e
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serve(pr, out); pr.Close() }()
	// Keep input reading separate so an aborted private operation cannot leave the
	// main process blocked waiting for the next controller frame.
	type inputEvent struct {
		line []byte
		err  error
		eof  bool
	}
	frames := make(chan inputEvent)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		scan := bufio.NewScanner(in)
		scan.Buffer(make([]byte, 4096), 65536)
		for scan.Scan() {
			select {
			case frames <- inputEvent{line: bytes.Clone(scan.Bytes())}:
			case <-stop:
				return
			}
		}
		select {
		case frames <- inputEvent{err: scan.Err(), eof: true}:
		case <-stop:
		}
	}()
	var seq uint32 = 1
	for {
		var event inputEvent
		select {
		case e := <-done:
			pw.Close()
			return e
		case event = <-frames:
		}
		if event.eof {
			pw.Close()
			if e := <-done; e != nil {
				return e
			}
			return event.err
		}
		var f signedFrame
		d := json.NewDecoder(bytes.NewReader(event.line))
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(&f) != nil || d.Decode(&extra) != io.EOF || f.Seq != seq || seq > maxOps {
			pw.CloseWithError(errors.New("controller frame refused"))
			<-done
			return errors.New("controller frame refused")
		}
		body, e := decode(f.Body, 1, 32767)
		sig, se := decode(f.Sig, 64, 64)
		h := appDigest(nonce, seq, body)
		if e != nil || se != nil || bytes.ContainsAny(body, "\r\n") || !ed25519.Verify(pub, h[:], sig) {
			pw.CloseWithError(errors.New("controller authentication failed"))
			<-done
			return errors.New("controller authentication failed")
		}
		seq++
		if _, e = pw.Write(append(body, '\n')); e != nil {
			pw.Close()
			return <-done
		}
		// close is only handled by the broker; stop reading after authenticated close.
		var q request
		if json.Unmarshal(body, &q) == nil && q.Op == "close" {
			pw.Close()
			return <-done
		}
	}
}
