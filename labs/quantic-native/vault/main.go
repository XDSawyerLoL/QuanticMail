package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

const domain = "quantic-vault-native-lab/v1"

type challenge struct {
	Domain string `json:"domain"`
	App    string `json:"app"`
	Scope  string `json:"scope"`
	Nonce  string `json:"nonce"`
	Key    string `json:"key"`
	Expiry int64  `json:"expiry"`
}
type response struct {
	Challenge challenge `json:"challenge"`
	Signature string    `json:"signature"`
}
type signer interface {
	Public() *ecdsa.PublicKey
	SignDigest([32]byte) ([]byte, error)
}
type authority struct {
	pending  challenge
	born     time.Time
	consumed bool
	pub      *ecdsa.PublicKey
}

func keyPin(p *ecdsa.PublicKey) string {
	h := sha256.Sum256(elliptic.Marshal(p.Curve, p.X, p.Y))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func issue(p *ecdsa.PublicKey, now time.Time) (*authority, error) {
	if p == nil || p.Curve != elliptic.P256() || p.X == nil || p.Y == nil || !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("invalid public key")
	}
	n := make([]byte, 32)
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return &authority{pending: challenge{domain, "lab-only", "device-proof", base64.RawURLEncoding.EncodeToString(n), keyPin(p), now.Add(30 * time.Second).UnixMilli()}, born: now, pub: &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y)}}, nil
}
func digest(c challenge) [32]byte { b, _ := json.Marshal(c); return sha256.Sum256(b) }
func approveAndSign(s signer, c challenge, now time.Time, approved bool) (response, error) {
	n, e := base64.RawURLEncoding.DecodeString(c.Nonce)
	if !approved || e != nil || len(n) != 32 || base64.RawURLEncoding.EncodeToString(n) != c.Nonce || c.Domain != domain || c.App != "lab-only" || c.Scope != "device-proof" || c.Key != keyPin(s.Public()) || c.Expiry <= now.UnixMilli() || c.Expiry-now.UnixMilli() > 30000 {
		return response{}, errors.New("authorization refused")
	}
	sig, e := s.SignDigest(digest(c))
	if e != nil {
		return response{}, e
	}
	if len(sig) != 64 {
		return response{}, errors.New("invalid signature length")
	}
	return response{c, base64.RawURLEncoding.EncodeToString(sig)}, nil
}
func (a *authority) verify(r response, now time.Time) bool {
	if a.consumed || now.Before(a.born) || now.Sub(a.born) >= 30*time.Second || now.UnixMilli() >= a.pending.Expiry || r.Challenge != a.pending {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(r.Signature)
	if e != nil || len(b) != 64 || base64.RawURLEncoding.EncodeToString(b) != r.Signature {
		return false
	}
	h := digest(r.Challenge)
	if !ecdsa.Verify(a.pub, h[:], new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:])) {
		return false
	}
	a.consumed = true
	return true
}
func main() {
	if handled, err := pqCLI(os.Args); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL CLOSED:", err)
			os.Exit(1)
		}
		return
	}
	if handled, err := portableCLI(os.Args); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL CLOSED:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "--init-replay-lab" {
		pub, e := appPublic(os.Args[5])
		if e == nil {
			e = initReplay(os.Args[2], os.Args[3], os.Args[4], hexHash(pub))
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 7 && os.Args[1] == "--broker-guarded-lab" {
		if e := runGuardedBroker(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "--provision-persistent-lab" {
		if err := provisionPersistent(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL CLOSED:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "--cleanup-persistent-lab" {
		if err := cleanupPersistent(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL CLOSED:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "--broker-persistent-lab" {
		if err := runPersistentBroker(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL CLOSED:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: --selftest or --broker-lab (Windows TPM signing); --broker-test-software (synthetic tests only)")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "--selftest":
		err = runNative()
	case "--broker-lab":
		err = runNativeBroker()
	case "--broker-test-software":
		err = runTestBroker()
	default:
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL CLOSED:", err)
		os.Exit(1)
	}
}
