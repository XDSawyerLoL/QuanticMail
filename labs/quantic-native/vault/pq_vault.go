package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const pqSuite = "QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1"

type pqKeys struct {
	kem, dsa                        pqKey
	address, device, kemPin, dsaPin string
	kemPub, dsaPub                  []byte
	recovery cipher.AEAD
}

func (p *pqKeys) close() { p.kem.close(); p.dsa.close() }
func pqMake(k, d pqKey, addr, device string) (*pqKeys, error) {
	kp, e := k.der(false)
	if e != nil {
		return nil, e
	}
	dp, e := d.der(false)
	if e != nil {
		return nil, e
	}
	return &pqKeys{k, d, addr, device, hexHash(kp), hexHash(dp), kp, dp, nil}, nil
}

var strongDevice = regexp.MustCompile(`^d-[0-9a-f]{32}$`)
var strongAddr = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{32}@quantic$`)
var msgID = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,100}$`)

func pqBinding(sign, enc, app, quorum, addr, device string) (string, error) {
	if !strongAddr.MatchString(addr) || !strongDevice.MatchString(device) {
		return "", portableRefusal
	}
	for _, v := range []string{sign, enc, app, quorum} {
		if !hashRE.MatchString(v) {
			return "", portableRefusal
		}
	}
	return "quantic-pq-sidecar-lab/v1\x00" + sign + enc + app + quorum + addr + "\x00" + device + "\x00", nil
}
func pqWrite(path, magic string, pw []byte, p *pqKeys) error {
	if !filepath.IsAbs(path) || !validPortablePassword(pw) {
		return portableRefusal
	}
	if e := checkPortableDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	sealed, e := encodePQStorage(magic, pw, p)
	if e != nil { return e }
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(sealed)
	if e == nil && n != len(sealed) {
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
		return e
	}
	return syncPortableDirectory(filepath.Dir(path))
}
// Platform-independent encrypted sidecar bytes; file custody is platform-specific.
func encodePQStorage(magic string, pw []byte, p *pqKeys) ([]byte,error) {
	if !validPortablePassword(pw) { return nil, portableRefusal }
	k, e := p.kem.der(true)
	if e != nil {
		return nil, e
	}
	defer clear(k)
	d, e := p.dsa.der(true)
	if e != nil {
		return nil, e
	}
	defer clear(d)
	raw, e := json.Marshal([][]byte{k, d})
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	salt, iv := make([]byte, 16), make([]byte, 12)
	if _, e = rand.Read(salt); e != nil {
		return nil, e
	}
	if _, e = rand.Read(iv); e != nil {
		return nil, e
	}
	g, e := portableAEAD(pw, salt)
	if e != nil {
		return nil, e
	}
	header := append(append([]byte(magic), salt...), iv...)
	return g.Seal(header, iv, raw, header), nil
}

func pqRead(path, magic string, pw []byte, addr, device, kpin, dpin string) (*pqKeys, error) {
	if !filepath.IsAbs(path) || !validPortablePassword(pw) || !hashRE.MatchString(kpin) || !hashRE.MatchString(dpin) {
		return nil, portableRefusal
	}
	if e := checkPortableDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || !privatePortableFile(info) || info.Size() > 50000 {
		return nil, portableRefusal
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return nil, portableRefusal
	}
 	b, e := io.ReadAll(io.LimitReader(f, 50001))
	if e != nil { return nil, portableRefusal }
	return decodePQStorage(b, magic, pw, addr, device, kpin, dpin)
}
func decodePQStorage(b []byte, magic string, pw []byte, addr, device, kpin, dpin string) (*pqKeys,error) {
	if !validPortablePassword(pw) || !hashRE.MatchString(kpin) || !hashRE.MatchString(dpin) { return nil, portableRefusal }
	h := len(magic)
	if len(b) < h+44 || len(b) > 50000 || string(b[:h]) != magic {
		return nil, portableRefusal
	}
	g, e := portableAEAD(pw, b[h:h+16])
	if e != nil {
		return nil, e
	}
	raw, e := g.Open(nil, b[h+16:h+28], b[h+28:], b[:h+28])
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	var der [][]byte
	if json.Unmarshal(raw, &der) != nil || len(der) != 2 {
		return nil, portableRefusal
	}
	defer clear(der[0])
	defer clear(der[1])
	k, e := pqImport(der[0], "ML-KEM-768")
	if e != nil {
		return nil, e
	}
	d, e := pqImport(der[1], "ML-DSA-65")
	if e != nil {
		k.close()
		return nil, e
	}
	p, e := pqMake(k, d, addr, device)
	if e != nil {
		k.close()
		d.close()
		return nil, e
	}
	if p.kemPin != kpin || p.dsaPin != dpin {
		p.close()
		return nil, portableRefusal
	}
	// Independent key domain derived from password and sidecar salt.
	salt:=sha256.Sum256(append([]byte("quantic-result-recovery-lab/v1\x00"+magic),b[h:h+16]...))
	p.recovery,e=portableAEAD(pw,salt[:16])
	if e!=nil{p.close();return nil,e}
	return p, nil
}

type pqContext struct {
	ClientMessageID string `json:"clientMessageId"`
	From            string `json:"from"`
	FromDeviceID    string `json:"fromDeviceId"`
	To              string `json:"to"`
	ToDeviceID      string `json:"toDeviceId"`
}
type pqEnvelope struct {
	CryptoSuite string        `json:"cryptoSuite"`
	KeyMode     string        `json:"keyMode"`
	Ephemeral   mailPublicJWK `json:"classicalEphemeralPublicKey"`
	KEM         string        `json:"pqKemCiphertext"`
	IV          string        `json:"iv"`
	Ciphertext  string        `json:"ciphertext"`
}

func (p *pqKeys) context(c pqContext) (string, error) {
	if !msgID.MatchString(c.ClientMessageID) || !strongAddr.MatchString(c.From) || !strongDevice.MatchString(c.FromDeviceID) || c.To != p.address || c.ToDeviceID != p.device {
		return "", portableRefusal
	}
	return strings.Join([]string{"quantic-hybrid-envelope-context-v1", pqSuite, c.ClientMessageID, c.From, c.FromDeviceID, c.To, c.ToDeviceID}, "\n"), nil
}
func (p *pqKeys) open(key agreementKey, c pqContext, v pqEnvelope) ([]byte, error) {
	ctx, e := p.context(c)
	if e != nil || v.CryptoSuite != pqSuite || v.KeyMode != "hybrid-static-fallback" {
		return nil, portableRefusal
	}
	j := v.Ephemeral
	if j.Kty != "EC" || j.Crv != "P-256" || len(j.KeyOps) != 0 {
		return nil, portableRefusal
	}
	x, e := decode(j.X, 32, 32)
	if e != nil {
		return nil, e
	}
	y, e := decode(j.Y, 32, 32)
	if e != nil {
		return nil, e
	}
	point, e := public(b64.EncodeToString(append(append([]byte{4}, x...), y...)))
	if e != nil {
		return nil, e
	}
	ct, e := decode(v.KEM, 1088, 1088)
	if e != nil {
		return nil, e
	}
	iv, e := decode(v.IV, 12, 12)
	if e != nil {
		return nil, e
	}
	enc, e := decode(v.Ciphertext, 17, maxPlain+16)
	if e != nil {
		return nil, e
	}
	z, e := key.ECDH(point)
	if e != nil {
		return nil, e
	}
	defer clear(z)
	pq, e := p.kem.dec(ct)
	if e != nil {
		return nil, e
	}
	defer clear(pq)
	salt := sha256.Sum256([]byte("quantic-hybrid-kdf-salt-v1\n" + ctx))
	mac := hmac.New(sha256.New, salt[:])
	mac.Write(z)
	mac.Write(pq)
	prk := mac.Sum(nil)
	defer clear(prk)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte(ctx))
	mac.Write([]byte{1})
	ak := mac.Sum(nil)
	defer clear(ak)
	block, e := aes.NewCipher(ak)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return g.Open(nil, iv, enc, []byte(ctx+"\nquantic-aes-gcm-aad-v1"))
}
func (p *pqKeys) proof(challenge string) ([]byte, error) {
	b, e := decode(challenge, 32, 32)
	if e != nil {
		return nil, e
	}
	m := append([]byte("quantic-pq-device-proof-lab/v1\x00"+p.address+"\x00"+p.device+"\x00"+p.kemPin+p.dsaPin), b...)
	return p.dsa.sign(m)
}
