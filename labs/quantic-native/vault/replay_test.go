package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testJournal(t *testing.T) (string, string, string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "journal")
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	if e := initReplay(p, a, b, c); e != nil {
		t.Fatal(e)
	}
	return p, a, b, c
}
func TestJournalRestartAndLock(t *testing.T) {
	p, a, b, c := testJournal(t)
	j, e := openReplay(p, a, b, c)
	if e != nil {
		t.Fatal(e)
	}
	k := replayID("packet", []byte("synthetic"))
	if e = j.consume(k); e != nil {
		t.Fatal(e)
	}
	if other, e := openReplay(p, a, b, c); e == nil {
		other.close()
		t.Fatal("second writer")
	}
	j.close()
	j, e = openReplay(p, a, b, c)
	if e != nil {
		t.Fatal(e)
	}
	defer j.close()
	if !j.has(k) || j.consume(k) == nil {
		t.Fatal("replay accepted")
	}
	if initReplay(p, a, b, c) == nil {
		t.Fatal("overwrite permitted")
	}
}
func TestJournalFailClosed(t *testing.T) {
	p, a, b, c := testJournal(t)
	if j, e := openReplay(p, a, b, a); e == nil {
		j.close()
		t.Fatal("wrong app pin")
	}
	j, e := openReplay(p, a, b, c)
	if e != nil {
		t.Fatal(e)
	}
	j.consume(replayID("packet", []byte("test")))
	j.close()
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	off := len(replayHeader) + 193 + 32
	f.WriteAt([]byte{raw[off] ^ 1}, int64(off))
	f.Close()
	if j, e = openReplay(p, a, b, c); e == nil {
		j.close()
		t.Fatal("corruption accepted")
	}
	os.Remove(p)
	if j, e = openReplay(p, a, b, c); e == nil {
		j.close()
		t.Fatal("missing accepted")
	}
}
func TestJournalTruncatedFails(t *testing.T) {
	p, a, b, c := testJournal(t)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{1})
	f.Close()
	if j, e := openReplay(p, a, b, c); e == nil {
		j.close()
		t.Fatal("partial write accepted")
	}
}
func TestGuardedBrokerRestart(t *testing.T) {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	p, a, b, c := testJournal(t)
	pkt, _ := seal(k.PublicKey(), []byte("test"))
	q, _ := json.Marshal(request{Op: "open", Packet: &pkt})
	for i := 0; i < 2; i++ {
		j, e := openReplay(p, a, b, c)
		if e != nil {
			t.Fatal(e)
		}
		var out bytes.Buffer
		calls := 0
		e = serveGuarded(softwareSigner{s}, k, "test", strings.NewReader(string(q)+"\n"), &out, func(string) bool { calls++; return true }, j)
		j.close()
		var r reply
		json.Unmarshal(out.Bytes(), &r)
		if e != nil || r.OK != (i == 0) || calls != 1-i {
			t.Fatal(i, r, e, calls)
		}
	}
}
func TestRollbackCounterexample(t *testing.T) {
	p, a, b, c := testJournal(t)
	old, _ := os.ReadFile(p)
	j, _ := openReplay(p, a, b, c)
	k := replayID("packet", []byte("test"))
	j.consume(k)
	j.close()
	os.WriteFile(p, old, 0600)
	j, e := openReplay(p, a, b, c)
	if e != nil {
		t.Fatal(e)
	}
	defer j.close()
	if j.has(k) {
		t.Fatal("expected rollback counterexample")
	}
}
func signedInput(priv ed25519.PrivateKey, nonce []byte, seq uint32, body string) string {
	d := appDigest(nonce, seq, []byte(body))
	f, _ := json.Marshal(signedFrame{seq, b64.EncodeToString([]byte(body)), b64.EncodeToString(ed25519.Sign(priv, d[:]))})
	return string(f) + "\n"
}
func channelTest(t *testing.T, mode string) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- authenticateFrames(pub, inR, outW, func(r io.Reader, w io.Writer) error { var data bytes.Buffer; _, e := io.Copy(&data, r); return e })
		outW.Close()
	}()
	var hello map[string]string
	if e := json.NewDecoder(outR).Decode(&hello); e != nil {
		t.Fatal(e)
	}
	nonce, _ := b64.DecodeString(hello["session"])
	seq := uint32(1)
	if mode == "wrongkey" {
		_, priv, _ = ed25519.GenerateKey(rand.Reader)
	}
	if mode == "oldsession" {
		nonce = make([]byte, 32)
	}
	if mode == "sequence" {
		seq = 2
	}
	frame := signedInput(priv, nonce, seq, `{"op":"public"}`)
	if mode == "replay" {
		frame += frame
	}
	inW.Write([]byte(frame))
	inW.Close()
	e := <-done
	if (e == nil) != (mode == "valid") {
		t.Fatal(mode, e)
	}
	outR.Close()
}
func TestSignedController(t *testing.T) {
	for _, m := range []string{"valid", "wrongkey", "oldsession", "sequence", "replay"} {
		t.Run(m, func(t *testing.T) { channelTest(t, m) })
	}
}

// Test-only child process: same synthetic P-256 keys on each invocation.
func TestGuardedChild(t *testing.T) {
	if os.Getenv("QV_TEST_CHILD") != "1" {
		return
	}
	kb := make([]byte, 32)
	kb[31] = 1
	key, e := ecdh.P256().NewPrivateKey(kb)
	if e != nil {
		os.Exit(2)
	}
	kb[31] = 2
	x, y := elliptic.P256().ScalarBaseMult(kb)
	s := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: new(big.Int).SetBytes(kb)}
	p := os.Getenv("QV_TEST_JOURNAL")
	app, _ := appPublic(os.Getenv("QV_TEST_APP"))
	j, e := openReplay(p, publicPin(s.Public()), publicPin(key.PublicKey()), hexHash(app))
	if e != nil {
		os.Exit(2)
	}
	defer j.close()
	if authenticateFrames(app, os.Stdin, os.Stdout, func(in io.Reader, out io.Writer) error {
		return serveGuarded(softwareSigner{s}, key, "test-child", in, out, func(string) bool { return true }, j)
	}) != nil {
		os.Exit(3)
	}
	os.Exit(0)
}
func TestInterprocessKillAndReplay(t *testing.T) {
	kb := make([]byte, 32)
	kb[31] = 1
	k, _ := ecdh.P256().NewPrivateKey(kb)
	kb[31] = 2
	x, y := elliptic.P256().ScalarBaseMult(kb)
	s := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	app, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(t.TempDir(), "journal")
	if e := initReplay(p, publicPin(s), publicPin(k.PublicKey()), hexHash(app)); e != nil {
		t.Fatal(e)
	}
	pkt, _ := seal(k.PublicKey(), []byte("synthetic"))
	body, _ := json.Marshal(request{Op: "open", Packet: &pkt})
	for i := 0; i < 2; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGuardedChild$")
		cmd.Env = append(os.Environ(), "QV_TEST_CHILD=1", "QV_TEST_JOURNAL="+p, "QV_TEST_APP="+b64.EncodeToString(app))
		in, _ := cmd.StdinPipe()
		out, _ := cmd.StdoutPipe()
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		reader := bufio.NewReader(out)
		line, e := reader.ReadBytes('\n')
		if e != nil {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal(e)
		}
		var hello map[string]string
		json.Unmarshal(line, &hello)
		nonce, _ := b64.DecodeString(hello["session"])
		in.Write([]byte(signedInput(priv, nonce, 1, string(body))))
		line, e = reader.ReadBytes('\n')
		var r reply
		json.Unmarshal(line, &r)
		cmd.Process.Kill()
		cmd.Wait()
		if e != nil || r.OK != (i == 0) {
			t.Fatal(i, e, string(line))
		}
	}
}
