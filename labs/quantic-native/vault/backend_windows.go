//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var dll = syscall.NewLazyDLL("ncrypt.dll")
var openProvider = dll.NewProc("NCryptOpenStorageProvider")
var createKey = dll.NewProc("NCryptCreatePersistedKey")
var setProperty = dll.NewProc("NCryptSetProperty")
var getProperty = dll.NewProc("NCryptGetProperty")
var finalize = dll.NewProc("NCryptFinalizeKey")
var exportKey = dll.NewProc("NCryptExportKey")
var signHash = dll.NewProc("NCryptSignHash")
var free = dll.NewProc("NCryptFreeObject")
var deleteKey = dll.NewProc("NCryptDeleteKey")

func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func status(op string, v uintptr) error {
	if uint32(v) != 0 {
		return fmt.Errorf("%s: 0x%08x", op, uint32(v))
	}
	return nil
}
func getDWORD(h uintptr, name string) (uint32, error) {
	var val, n uint32
	r, _, _ := getProperty.Call(h, uintptr(unsafe.Pointer(wide(name))), uintptr(unsafe.Pointer(&val)), 4, uintptr(unsafe.Pointer(&n)), 0)
	if e := status(name, r); e != nil {
		return 0, e
	}
	if n != 4 {
		return 0, errors.New("invalid property size")
	}
	return val, nil
}
func setDWORD(h uintptr, name string, val uint32) error {
	r, _, _ := setProperty.Call(h, uintptr(unsafe.Pointer(wide(name))), uintptr(unsafe.Pointer(&val)), 4, 0)
	return status(name, r)
}

type tpmSigner struct {
	h   uintptr
	pub *ecdsa.PublicKey
}

func (s *tpmSigner) Public() *ecdsa.PublicKey { return s.pub }
func (s *tpmSigner) SignDigest(d [32]byte) ([]byte, error) {
	buf := make([]byte, 64)
	var n uint32
	r, _, _ := signHash.Call(s.h, 0, uintptr(unsafe.Pointer(&d[0])), 32, uintptr(unsafe.Pointer(&buf[0])), 64, uintptr(unsafe.Pointer(&n)), 0)
	if e := status("NCryptSignHash", r); e != nil {
		return nil, e
	}
	if n != 64 {
		return nil, errors.New("invalid P-256 signature size")
	}
	return buf, nil
}
func withTPMSigner(fn func(signer) error) (err error) {
	var prov, key uintptr
	r, _, _ := openProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(wide("Microsoft Platform Crypto Provider"))), 0)
	if e := status("open TPM provider", r); e != nil {
		return e
	}
	defer free.Call(prov)
	impl, e := getDWORD(prov, "Impl Type")
	if e != nil {
		return e
	}
	if impl&1 == 0 {
		return errors.New("provider does not report hardware implementation")
	}
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return e
	}
	name := "QuanticVault-Lab-" + hex.EncodeToString(random)
	r, _, _ = createKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(wide("ECDSA_P256"))), uintptr(unsafe.Pointer(wide(name))), 0, 0)
	if e = status("create key", r); e != nil {
		return e
	}
	defer func() {
		v, _, _ := deleteKey.Call(key, 0)
		if e := status("delete synthetic key "+name, v); e != nil {
			free.Call(key)
			if err == nil {
				err = e
			}
		}
	}()
	if e = setDWORD(key, "Export Policy", 0); e != nil {
		return e
	}
	if e = setDWORD(key, "Key Usage", 2); e != nil {
		return e
	}
	r, _, _ = finalize.Call(key, 0)
	if e = status("finalize key", r); e != nil {
		return e
	}
	policy, e := getDWORD(key, "Export Policy")
	if e != nil {
		return e
	}
	if policy != 0 {
		return errors.New("private key export enabled")
	}
	var n uint32
	// A private export sizing query must fail. Never allocate a private blob.
	r, _, _ = exportKey.Call(key, 0, uintptr(unsafe.Pointer(wide("ECCPRIVATEBLOB"))), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if uint32(r) == 0 {
		return errors.New("private export query unexpectedly allowed")
	}
	buf := make([]byte, 72)
	n = 0
	r, _, _ = exportKey.Call(key, 0, uintptr(unsafe.Pointer(wide("ECCPUBLICBLOB"))), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), 0)
	if e = status("export public key", r); e != nil {
		return e
	}
	if n != 72 || binary.LittleEndian.Uint32(buf[:4]) != 0x31534345 || binary.LittleEndian.Uint32(buf[4:8]) != 32 {
		return errors.New("invalid public P-256 blob")
	}
	p := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(buf[8:40]), Y: new(big.Int).SetBytes(buf[40:72])}
	s := &tpmSigner{key, p}
	return fn(s)
}
func runNative() error {
	return withTPMSigner(func(s signer) error {
		a, e := issue(s.Public(), time.Now())
		if e != nil {
			return e
		}
		proof, e := approveAndSign(s, a.pending, time.Now(), true)
		if e != nil {
			return e
		}
		if !a.verify(proof, time.Now()) || a.verify(proof, time.Now()) {
			return errors.New("signature/replay validation failed")
		}
		fmt.Println("PASS: TPM provider, zero export policy, refused private export query, valid P-256 proof, replay rejected. Synthetic key cleanup follows.")
		return nil
	})
}
func runNativeBroker() error {
	return withTPMSigner(func(s signer) error {
		return serveBroker(s, "tpm-signing/software-ephemeral-ecdh", os.Stdin, os.Stdout)
	})
}
