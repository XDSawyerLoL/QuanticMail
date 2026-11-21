package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
)

// Explicit software provider. It is not a hardware-backed or nonexportable key store.
// The file format uses fixed PBKDF2-HMAC-SHA256 and AES-256-GCM parameters.
const portableMagic = "QV-SOFTWARE-LAB-V1\x00"
const anchoredMagic = "QV-SOFTWARE-LAB-ANCHOR-V1\x00"
const portableIterations = 600000
const portableLen = len(portableMagic) + 16 + 12 + 64 + 16
const portableBackend = "software-encrypted-persistent-lab"

var portableRefusal = errors.New("software vault refused")

type portableKeys struct {
	signing   *ecdsa.PrivateKey
	agreement *ecdh.PrivateKey
}

// PBKDF2-HMAC-SHA256, one 32-byte output block (RFC 8018).
func derivePortable(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	t := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range t {
			t[j] ^= u[j]
		}
	}
	clear(u)
	return t
}
func portableAEAD(password, salt []byte) (cipher.AEAD, error) {
	k := derivePortable(password, salt, portableIterations)
	defer clear(k)
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func portablePins(k portableKeys) (string, string) {
	return publicPin(&k.signing.PublicKey), publicPin(k.agreement.PublicKey())
}
func freshPortable() (portableKeys, error) {
	s, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return portableKeys{}, e
	}
	a, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return portableKeys{}, e
	}
	return portableKeys{s, a}, nil
}
func validPortablePassword(p []byte) bool { return len(p) >= 20 && len(p) <= 1024 }
func encryptPortable(k portableKeys, password []byte) ([]byte, error) {
	return encryptPortableMode(k, password, portableMagic)
}
func encryptPortableMode(k portableKeys, password []byte, magic string) ([]byte, error) {
	if !validPortablePassword(password) {
		return nil, errors.New("software vault requires a unique high-entropy passphrase of at least 20 bytes")
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	g, e := portableAEAD(password, salt)
	if e != nil {
		return nil, e
	}
	header := append([]byte(magic), salt...)
	header = append(header, nonce...)
	plain := k.signing.D.FillBytes(make([]byte, 32))
	agreement := k.agreement.Bytes()
	plain = append(plain, agreement...)
	clear(agreement)
	defer clear(plain)
	return g.Seal(header, nonce, plain, header), nil
}
func decryptPortable(raw, password []byte) (portableKeys, error) {
	return decryptPortableMode(raw, password, portableMagic)
}
func decryptPortableMode(raw, password []byte, magic string) (portableKeys, error) {
	if len(raw) != len(magic)+16+12+64+16 || string(raw[:len(magic)]) != magic || !validPortablePassword(password) {
		return portableKeys{}, portableRefusal
	}
	h := len(magic)
	salt, nonce := raw[h:h+16], raw[h+16:h+28]
	header := raw[:h+28]
	g, e := portableAEAD(password, salt)
	if e != nil {
		return portableKeys{}, portableRefusal
	}
	plain, e := g.Open(nil, nonce, raw[h+28:], header)
	if e != nil {
		return portableKeys{}, portableRefusal
	}
	defer clear(plain)
	// Reuse standard library scalar validation and public-point computation.
	s, e := ecdh.P256().NewPrivateKey(plain[:32])
	if e != nil {
		return portableKeys{}, portableRefusal
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), s.PublicKey().Bytes())
	if x == nil {
		return portableKeys{}, portableRefusal
	}
	priv, e := ecdsaFromBytes(plain[:32], x, y)
	if e != nil {
		return portableKeys{}, portableRefusal
	}
	a, e := ecdh.P256().NewPrivateKey(plain[32:])
	if e != nil {
		return portableKeys{}, portableRefusal
	}
	return portableKeys{priv, a}, nil
}
func ecdsaFromBytes(b []byte, x, y *big.Int) (*ecdsa.PrivateKey, error) {
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: new(big.Int).SetBytes(b)}, nil
}
func provisionSoftware(path string, password []byte) (portableKeys, error) {
	return provisionSoftwareMode(path, password, portableMagic)
}
func provisionSoftwareMode(path string, password []byte, magic string) (portableKeys, error) {
	if !filepath.IsAbs(path) {
		return portableKeys{}, portableRefusal
	}
	if e := checkPortableDirectory(filepath.Dir(path)); e != nil {
		return portableKeys{}, e
	}
	k, e := freshPortable()
	if e != nil {
		return portableKeys{}, e
	}
	raw, e := encryptPortableMode(k, password, magic)
	if e != nil {
		return portableKeys{}, e
	}
	// O_EXCL never overwrites an identity. Partial files fail closed and require manual recovery.
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return portableKeys{}, e
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return portableKeys{}, e
	}
	if e = syncPortableDirectory(filepath.Dir(path)); e != nil {
		return portableKeys{}, e
	}
	return k, nil
}
func openSoftware(path string, password []byte, signPin, encPin string) (portableKeys, error) {
	return openSoftwareMode(path, password, signPin, encPin, portableMagic)
}
func openSoftwareMode(path string, password []byte, signPin, encPin, magic string) (portableKeys, error) {
	size := len(magic) + 16 + 12 + 64 + 16
	if !filepath.IsAbs(path) || !hashRE.MatchString(signPin) || !hashRE.MatchString(encPin) {
		return portableKeys{}, portableRefusal
	}
	if e := checkPortableDirectory(filepath.Dir(path)); e != nil {
		return portableKeys{}, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() != int64(size) || !privatePortableFile(info) {
		return portableKeys{}, portableRefusal
	}
	f, e := os.Open(path)
	if e != nil {
		return portableKeys{}, portableRefusal
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return portableKeys{}, portableRefusal
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(size+1)))
	if e != nil {
		return portableKeys{}, portableRefusal
	}
	k, e := decryptPortableMode(raw, password, magic)
	if e != nil {
		return portableKeys{}, e
	}
	s, a := portablePins(k)
	if s != signPin || a != encPin {
		return portableKeys{}, portableRefusal
	}
	return k, nil
}
func runSoftwareProvision(path string) error { return runSoftwareProvisionMode(path, portableMagic) }
func runSoftwareProvisionMode(path, magic string) error {
	p, e := localSecret("Nouveau coffre logiciel de laboratoire (aucun TPM). Phrase secrète : ")
	if e != nil {
		return e
	}
	defer clear(p)
	q, e := localSecret("Confirmer la phrase secrète : ")
	if e != nil {
		return e
	}
	defer clear(q)
	if !equalSecret(p, q) {
		return portableRefusal
	}
	k, e := provisionSoftwareMode(path, p, magic)
	if e != nil {
		return e
	}
	s, a := portablePins(k)
	backend := portableBackend
	if magic != portableMagic {
		backend = "software-anchored-persistent-lab"
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"backend": backend, "signingPin": s, "encryptionPin": a, "signing": b64.EncodeToString(elliptic.Marshal(elliptic.P256(), k.signing.X, k.signing.Y)), "encryption": b64.EncodeToString(k.agreement.PublicKey().Bytes())})
}
func runSoftwareBroker(path, signPin, encPin, app, journal string) error {
	return runSoftwareBrokerAnchor(path, signPin, encPin, app, journal, nil, "")
}
func runSoftwareBrokerAnchor(path, signPin, encPin, app, journal string, a checkpointAnchor, serverPin string) error {
	pub, e := appPublic(app)
	if e != nil {
		return e
	}
	if filepath.Dir(path) != filepath.Dir(journal) {
		return errors.New("journal must be in the same private directory")
	}
	p, e := localSecret("Ouvrir le coffre LOGICIEL de laboratoire : ")
	if e != nil {
		return e
	}
	defer clear(p)
	magic := portableMagic
	backend := portableBackend
	if a != nil {
		magic = anchoredMagic + serverPin + "\x00"
		backend = "software-anchored-persistent-lab"
	}
	k, e := openSoftwareMode(path, p, signPin, encPin, magic)
	clear(p)
	if e != nil {
		return e
	}
	info, e := os.Lstat(journal)
	if e != nil || !info.Mode().IsRegular() || !privatePortableFile(info) {
		return portableRefusal
	}
	j, e := openReplay(journal, signPin, encPin, hexHash(pub))
	if e != nil {
		return e
	}
	defer j.close()
	if a != nil {
		id, e := anchorID(signPin, encPin, hexHash(pub))
		if e != nil {
			return e
		}
		if e = j.attachAnchor(a, id); e != nil {
			return e
		}
	}
	return authenticateFrames(pub, os.Stdin, os.Stdout, func(in io.Reader, out io.Writer) error {
		return serveGuarded(softwareSigner{k.signing}, k.agreement, backend, in, out, localPortableApproval, j)
	})
}
func portableCLI(args []string) (bool, error) {
	if len(args) == 2 && args[1] == "--providers" {
		return true, json.NewEncoder(os.Stdout).Encode(map[string]any{"software": portableBackend, "softwareAnchored": "software-anchored-persistent-lab", "softwareAvailable": runtime.GOOS == "linux", "hardwareWindows": "optional-adapter", "windowsAdapterCompiled": runtime.GOOS == "windows", "hardwareDetection": "not-probed", "hardwareIndependent": "not-implemented", "automaticFallback": false})
	}
	if len(args) == 4 && args[1] == "--provision-software-fresh-manifest-quorum-lab" {
		if !hashRE.MatchString(args[3]) {
			return true, errors.New("trusted quorum fingerprint required")
		}
		return true, runSoftwareProvisionMode(args[2], anchoredMagic+"fresh-manifest-quorum:"+args[3]+"\x00")
	}
	if len(args) == 8 && args[1] == "--broker-software-fresh-manifest-quorum-lab" {
		a, e := newQuorumAnchor(args[7])
		if e != nil {
			return true, e
		}
		return true, runSoftwareBrokerAnchor(args[2], args[3], args[4], args[5], args[6], &freshQuorum{q: a}, "fresh-manifest-quorum:"+a.pin)
	}
	if len(args) == 4 && args[1] == "--provision-software-scheduled-manifest-quorum-lab" {
		if !hashRE.MatchString(args[3]) {
			return true, errors.New("trusted quorum fingerprint required")
		}
		return true, runSoftwareProvisionMode(args[2], anchoredMagic+"scheduled-manifest-quorum:"+args[3]+"\x00")
	}
	if len(args) == 8 && args[1] == "--broker-software-scheduled-manifest-quorum-lab" {
		a, e := newQuorumAnchor(args[7])
		if e != nil {
			return true, e
		}
		return true, runSoftwareBrokerAnchor(args[2], args[3], args[4], args[5], args[6], &freshQuorum{q: a, scheduled: true}, "scheduled-manifest-quorum:"+a.pin)
	}
	if len(args) == 4 && args[1] == "--provision-software-compact-manifest-quorum-lab" {
		if !hashRE.MatchString(args[3]) {
			return true, errors.New("trusted quorum fingerprint required")
		}
		return true, runSoftwareProvisionMode(args[2], anchoredMagic+"compact-manifest-quorum:"+args[3]+"\x00")
	}
	if len(args) == 8 && args[1] == "--broker-software-compact-manifest-quorum-lab" {
		a, e := newQuorumAnchor(args[7])
		if e != nil {
			return true, e
		}
		return true, runSoftwareBrokerAnchor(args[2], args[3], args[4], args[5], args[6], &freshQuorum{q: a, scheduled: true, compact: true}, "compact-manifest-quorum:"+a.pin)
	}
	if len(args) == 4 && args[1] == "--provision-software-manifest-quorum-lab" {
		if !hashRE.MatchString(args[3]) {
			return true, errors.New("trusted quorum fingerprint required")
		}
		return true, runSoftwareProvisionMode(args[2], anchoredMagic+"manifest-quorum:"+args[3]+"\x00")
	}
	if len(args) == 8 && args[1] == "--broker-software-manifest-quorum-lab" {
		a, e := newQuorumAnchor(args[7])
		if e != nil {
			return true, e
		}
		return true, runSoftwareBrokerAnchor(args[2], args[3], args[4], args[5], args[6], a, "manifest-quorum:"+a.pin)
	}
	if len(args) == 4 && args[1] == "--provision-software-quorum-lab" {
		if !hashRE.MatchString(args[3]) {
			return true, errors.New("trusted quorum fingerprint required")
		}
		return true, runSoftwareProvisionMode(args[2], anchoredMagic+"quorum:"+args[3]+"\x00")
	}
	if len(args) == 8 && args[1] == "--broker-software-quorum-lab" {
		a, e := newQuorumAnchor(args[7])
		if e != nil {
			return true, e
		}
		return true, runSoftwareBrokerAnchor(args[2], args[3], args[4], args[5], args[6], a, "quorum:"+a.pin)
	}
	if len(args) == 4 && args[1] == "--provision-software-anchored-lab" {
		if !hashRE.MatchString(args[3]) {
			return true, errors.New("trusted authority certificate pin required")
		}
		return true, runSoftwareProvisionMode(args[2], anchoredMagic+args[3]+"\x00")
	}
	if len(args) == 3 && args[1] == "--provision-software-lab" {
		return true, runSoftwareProvision(args[2])
	}
	if len(args) == 8 && args[1] == "--broker-software-anchored-lab" {
		a, e := newRemoteAnchor(args[7])
		if e != nil {
			return true, e
		}
		return true, runSoftwareBrokerAnchor(args[2], args[3], args[4], args[5], args[6], a, a.serverPin)
	}
	if len(args) == 7 && args[1] == "--broker-software-guarded-lab" {
		return true, runSoftwareBroker(args[2], args[3], args[4], args[5], args[6])
	}
	return false, nil
}
