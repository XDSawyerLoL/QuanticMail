//go:build windows

package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"syscall"
	"unsafe"
)

var openKey = dll.NewProc("NCryptOpenKey")
var importKey = dll.NewProc("NCryptImportKey")
var agree = dll.NewProc("NCryptSecretAgreement")
var derive = dll.NewProc("NCryptDeriveKey")
var messageBox = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
var profileRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

const prefix = "QuanticVault-Persistent-Lab-"

// This is a local confirmation prompt, NOT an authenticated secure desktop or
// evidence of caller identity. It is never exposed to the web renderer.
func nativeApproval(detail string) bool {
	r, _, _ := messageBox.Call(0, uintptr(unsafe.Pointer(wide("Laboratoire Identity Vault — aucune identité réelle.\n\n"+detail+"\n\nAutoriser cette opération ?"))), uintptr(unsafe.Pointer(wide("Quantic Vault — test matériel"))), 0x4|0x30|0x100|0x10000)
	return r == 6 // IDYES, default No
}
func provider() (uintptr, error) {
	var p uintptr
	r, _, _ := openProvider.Call(uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(wide("Microsoft Platform Crypto Provider"))), 0)
	if e := status("open TPM provider", r); e != nil {
		return 0, e
	}
	impl, e := getDWORD(p, "Impl Type")
	if e != nil || impl&1 == 0 {
		free.Call(p)
		return 0, errors.New("hardware provider required")
	}
	return p, nil
}
func makePersistent(p uintptr, name, alg string, usage uint32) (uintptr, error) {
	var k uintptr
	r, _, _ := createKey.Call(p, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(wide(alg))), uintptr(unsafe.Pointer(wide(name))), 0, 0)
	if e := status("create unique lab key", r); e != nil {
		return 0, e
	}
	ok := false
	defer func() {
		if !ok {
			if r, _, _ := deleteKey.Call(k, 0); uint32(r) != 0 {
				free.Call(k)
				fmt.Fprintln(os.Stderr, "Cleanup needed for lab key", name)
			}
		}
	}()
	if e := setDWORD(k, "Export Policy", 0); e != nil {
		return 0, e
	}
	if e := setDWORD(k, "Key Usage", usage); e != nil {
		return 0, e
	}
	r, _, _ = finalize.Call(k, 0)
	if e := status("finalize lab key", r); e != nil {
		return 0, e
	}
	ok = true
	return k, nil
}
func openPersistent(p uintptr, name string) (uintptr, error) {
	var k uintptr
	r, _, _ := openKey.Call(p, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(wide(name))), 0, 0)
	if e := status("open existing lab key", r); e != nil {
		return 0, e
	}
	return k, nil
}
func publicBlob(k uintptr, magic, usage uint32) ([]byte, error) {
	policy, e := getDWORD(k, "Export Policy")
	if e != nil || policy != 0 {
		return nil, errors.New("nonexportable policy required")
	}
	u, e := getDWORD(k, "Key Usage")
	if e != nil || u != usage {
		return nil, errors.New("unexpected key usage")
	}
	var n uint32
	r, _, _ := exportKey.Call(k, 0, uintptr(unsafe.Pointer(wide("ECCPRIVATEBLOB"))), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if uint32(r) == 0 {
		return nil, errors.New("private export sizing unexpectedly allowed")
	}
	buf := make([]byte, 72)
	r, _, _ = exportKey.Call(k, 0, uintptr(unsafe.Pointer(wide("ECCPUBLICBLOB"))), 0, uintptr(unsafe.Pointer(&buf[0])), 72, uintptr(unsafe.Pointer(&n)), 0)
	if e := status("public export", r); e != nil {
		return nil, e
	}
	if n != 72 || binary.LittleEndian.Uint32(buf[:4]) != magic || binary.LittleEndian.Uint32(buf[4:8]) != 32 {
		return nil, errors.New("unexpected public blob")
	}
	return append([]byte{4}, buf[8:]...), nil
}

type tpmAgreement struct {
	provider, key uintptr
	pub           *ecdh.PublicKey
}

func (k *tpmAgreement) PublicKey() *ecdh.PublicKey { return k.pub }
func (k *tpmAgreement) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	if peer == nil || peer.Curve() != ecdh.P256() {
		return nil, errors.New("invalid peer")
	}
	b := peer.Bytes()
	blob := make([]byte, 72)
	binary.LittleEndian.PutUint32(blob[:4], 0x314b4345)
	binary.LittleEndian.PutUint32(blob[4:8], 32)
	copy(blob[8:], b[1:])
	var remote, secret uintptr
	r, _, _ := importKey.Call(k.provider, 0, uintptr(unsafe.Pointer(wide("ECCPUBLICBLOB"))), 0, uintptr(unsafe.Pointer(&remote)), uintptr(unsafe.Pointer(&blob[0])), 72, 0)
	if e := status("import public peer", r); e != nil {
		return nil, e
	}
	defer free.Call(remote)
	r, _, _ = agree.Call(k.key, remote, uintptr(unsafe.Pointer(&secret)), 0)
	if e := status("TPM ECDH", r); e != nil {
		return nil, e
	}
	defer free.Call(secret)
	var n uint32
	z := make([]byte, 32)
	r, _, _ = derive.Call(secret, uintptr(unsafe.Pointer(wide("TRUNCATE"))), 0, uintptr(unsafe.Pointer(&z[0])), 32, uintptr(unsafe.Pointer(&n)), 0)
	if e := status("CNG raw secret", r); e != nil {
		clear(z)
		return nil, e
	}
	if n != 32 {
		clear(z)
		return nil, errors.New("unexpected derived secret size")
	}
	return reverseSecret(z), nil
}
func handles(p, s, e uintptr) (*tpmSigner, *tpmAgreement, error) {
	sb, err := publicBlob(s, 0x31534345, 2)
	if err != nil {
		return nil, nil, err
	}
	eb, err := publicBlob(e, 0x314b4345, 4)
	if err != nil {
		return nil, nil, err
	}
	if _, err = ecdh.P256().NewPublicKey(sb); err != nil {
		return nil, nil, err
	}
	ep, err := ecdh.P256().NewPublicKey(eb)
	if err != nil {
		return nil, nil, err
	}
	return &tpmSigner{s, &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(sb[1:33]), Y: new(big.Int).SetBytes(sb[33:])}}, &tpmAgreement{p, e, ep}, nil
}
func verifyAgreement(k agreementKey) error {
	other, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	a, e := k.ECDH(other.PublicKey())
	if e != nil {
		return e
	}
	defer clear(a)
	b, e := other.ECDH(k.PublicKey())
	if e != nil {
		return e
	}
	defer clear(b)
	if !equalSecret(a, b) {
		return errors.New("ECDH interoperability failed")
	}
	return nil
}
func provisionPersistent(profile string) error {
	if !profileRE.MatchString(profile) {
		return errors.New("invalid lab profile")
	}
	if !nativeApproval("Créer deux clés persistantes de test. Profil : " + profile) {
		return errors.New("local consent refused")
	}
	p, e := provider()
	if e != nil {
		return e
	}
	defer free.Call(p)
	s, e := makePersistent(p, prefix+profile+"-sign", "ECDSA_P256", 2)
	if e != nil {
		return e
	}
	defer free.Call(s)
	// Never overwrite or reuse an existing name; a partial provision is left for
	// explicit lab-only administrative cleanup, never silently replaced.
	k, e := makePersistent(p, prefix+profile+"-enc", "ECDH_P256", 4)
	if e != nil {
		return e
	}
	defer free.Call(k)
	signer, key, e := handles(p, s, k)
	if e != nil {
		return e
	}
	if e = verifyAgreement(key); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"profile": profile, "signingPin": publicPin(signer.Public()), "encryptionPin": publicPin(key.PublicKey()), "backend": "tpm-persistent-lab"})
}
func runPersistentBroker(profile, signPin, encPin string) error {
	return errors.New("RC3 requires authenticated controller and existing replay journal; use --broker-guarded-lab")
}
func runGuardedBroker(profile, signPin, encPin, app, journal string) error {
	if !profileRE.MatchString(profile) || !hashRE.MatchString(signPin) || !hashRE.MatchString(encPin) {
		return errors.New("invalid profile or pins")
	}
	p, e := provider()
	if e != nil {
		return e
	}
	defer free.Call(p)
	s, e := openPersistent(p, prefix+profile+"-sign")
	if e != nil {
		return e
	}
	defer free.Call(s)
	k, e := openPersistent(p, prefix+profile+"-enc")
	if e != nil {
		return e
	}
	defer free.Call(k)
	signer, key, e := handles(p, s, k)
	if e != nil {
		return e
	}
	if publicPin(signer.Public()) != signPin || publicPin(key.PublicKey()) != encPin {
		return errors.New("public pin mismatch")
	}
	if e = verifyAgreement(key); e != nil {
		return e
	}
	pub, err := appPublic(app)
	if err != nil {
		return err
	}
	j, err := openReplay(journal, signPin, encPin, hexHash(pub))
	if err != nil {
		return err
	}
	defer j.close()
	return authenticateFrames(pub, os.Stdin, os.Stdout, func(in io.Reader, out io.Writer) error {
		return serveGuarded(signer, key, "tpm-persistent-lab-guarded", in, out, nativeApproval, j)
	})
}
func cleanupPersistent(profile, signPin, encPin string) error {
	if !profileRE.MatchString(profile) || !hashRE.MatchString(signPin) || !hashRE.MatchString(encPin) {
		return errors.New("invalid profile or pins")
	}
	p, e := provider()
	if e != nil {
		return e
	}
	defer free.Call(p)
	s, e := openPersistent(p, prefix+profile+"-sign")
	if e != nil {
		return e
	}
	defer func() {
		if s != 0 {
			free.Call(s)
		}
	}()
	k, e := openPersistent(p, prefix+profile+"-enc")
	if e != nil {
		return e
	}
	defer func() {
		if k != 0 {
			free.Call(k)
		}
	}()
	signer, key, e := handles(p, s, k)
	if e != nil {
		return e
	}
	if publicPin(signer.Public()) != signPin || publicPin(key.PublicKey()) != encPin {
		return errors.New("public pin mismatch")
	}
	if !nativeApproval("Supprimer uniquement les deux clés synthétiques du profil de test : " + profile) {
		return errors.New("local consent refused")
	}
	r, _, _ := deleteKey.Call(k, 0)
	if e = status("delete lab encryption key", r); e != nil {
		return e
	}
	k = 0
	r, _, _ = deleteKey.Call(s, 0)
	if e = status("delete lab signing key", r); e != nil {
		return e
	}
	s = 0
	return nil
}
