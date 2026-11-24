package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// An isolated, one-use laboratory protocol over anonymous inherited pipes.
// The parent is trusted for the experiment. No listener, persistent key, or real identity.
const brokerDomain = "quantic-vault-isolated-lab/v1"
const maxPlain = 8192
const maxOps = 256

var b64 = base64.RawURLEncoding

type softwareSigner struct{ k *ecdsa.PrivateKey }

func (s softwareSigner) Public() *ecdsa.PublicKey { return &s.k.PublicKey }
func (s softwareSigner) SignDigest(d [32]byte) ([]byte, error) {
	r, v, e := ecdsa.Sign(rand.Reader, s.k, d[:])
	if e != nil {
		return nil, e
	}
	return append(r.FillBytes(make([]byte, 32)), v.FillBytes(make([]byte, 32))...), nil
}
func runTestBroker() error {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	return serveBroker(softwareSigner{k}, "software-test-only", os.Stdin, os.Stdout)
}

type packet struct {
	Ephemeral  string `json:"ephemeral"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}
type request struct {
	Recover bool `json:"recover,omitempty"`
	SenderAuth *senderAuth `json:"senderAuth,omitempty"`
	PQContext   *pqContext    `json:"pqContext,omitempty"`
	PQEnvelope  *pqEnvelope   `json:"pqEnvelope,omitempty"`
	PQChallenge string        `json:"pqChallenge,omitempty"`
	Enrollment  string        `json:"enrollment,omitempty"`
	Mail        *mailEnvelope `json:"mail,omitempty"`
	Op          string        `json:"op"`
	Recipient   string        `json:"recipient,omitempty"`
	Message     string        `json:"message,omitempty"`
	Packet      *packet       `json:"packet,omitempty"`
	Challenge   *challenge    `json:"challenge,omitempty"`
	Approved    bool          `json:"approved,omitempty"`
}
type reply struct {
	HybridEnvelope *pqEnvelope `json:"pqEnvelope,omitempty"`
	SenderAuth *senderAuth `json:"senderAuth,omitempty"`
	PQKEM           string     `json:"pqKem,omitempty"`
	PQDSA           string     `json:"pqDsa,omitempty"`
	PQProof         string     `json:"pqProof,omitempty"`
	EnrollmentProof string     `json:"enrollmentProof,omitempty"`
	OK              bool       `json:"ok"`
	Error           string     `json:"error,omitempty"`
	Backend         string     `json:"backend,omitempty"`
	Signing         string     `json:"signing,omitempty"`
	Encryption      string     `json:"encryption,omitempty"`
	Packet          *packet    `json:"packet,omitempty"`
	Message         *string    `json:"message,omitempty"`
	Challenge       *challenge `json:"challenge,omitempty"`
	Proof           *response  `json:"proof,omitempty"`
}

func decode(s string, min, max int) ([]byte, error) {
	if len(s) > ((max+2)/3)*4 {
		return nil, errors.New("size")
	}
	b, e := b64.DecodeString(s)
	if e != nil || len(b) < min || len(b) > max || b64.EncodeToString(b) != s {
		return nil, errors.New("encoding")
	}
	return b, nil
}
func public(s string) (*ecdh.PublicKey, error) {
	b, e := decode(s, 65, 65)
	if e != nil {
		return nil, e
	}
	return ecdh.P256().NewPublicKey(b)
}

// HKDF-SHA256 extract/expand for a single 32-byte AES key with public context.
func context(ephemeral, recipient []byte) []byte {
	b := []byte(brokerDomain + "/message\x00")
	b = append(b, ephemeral...)
	return append(b, recipient...)
}
func aead(secret, ctx []byte) (cipher.AEAD, error) {
	extract := hmac.New(sha256.New, make([]byte, 32))
	extract.Write(secret)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write(ctx)
	expand.Write([]byte{1})
	key := expand.Sum(nil)
	defer func() { clear(secret); clear(prk); clear(key) }()
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func seal(recipient *ecdh.PublicKey, plain []byte) (packet, error) {
	if len(plain) > maxPlain {
		return packet{}, errors.New("size")
	}
	eph, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return packet{}, e
	}
	z, e := eph.ECDH(recipient)
	if e != nil {
		return packet{}, e
	}
	ep := eph.PublicKey().Bytes()
	ctx := context(ep, recipient.Bytes())
	g, e := aead(z, ctx)
	if e != nil {
		return packet{}, e
	}
	n := make([]byte, 12)
	if _, e = rand.Read(n); e != nil {
		return packet{}, e
	}
	return packet{b64.EncodeToString(ep), b64.EncodeToString(n), b64.EncodeToString(g.Seal(nil, n, plain, ctx))}, nil
}

type agreementKey interface {
	PublicKey() *ecdh.PublicKey
	ECDH(*ecdh.PublicKey) ([]byte, error)
}

func unseal(key agreementKey, p packet) ([]byte, error) {
	ep, e := public(p.Ephemeral)
	if e != nil {
		return nil, e
	}
	n, e := decode(p.Nonce, 12, 12)
	if e != nil {
		return nil, e
	}
	c, e := decode(p.Ciphertext, 16, maxPlain+16)
	if e != nil {
		return nil, e
	}
	z, e := key.ECDH(ep)
	if e != nil {
		return nil, e
	}
	ctx := context(ep.Bytes(), key.PublicKey().Bytes())
	g, e := aead(z, ctx)
	if e != nil {
		return nil, e
	}
	return g.Open(nil, n, c, ctx)
}
func serveBroker(s signer, backend string, in io.Reader, out io.Writer) error {
	key, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	return serveWithKey(s, key, backend, in, out, func(string) bool { return true })
}

// approve is supplied by the isolated trusted-process UI, never by IPC fields alone.
func serveWithKey(s signer, key agreementKey, backend string, in io.Reader, out io.Writer, approve func(string) bool) error {
	return serveGuarded(s, key, backend, in, out, approve, nil)
}

func serveGuarded(s signer, key agreementKey, backend string, in io.Reader, out io.Writer, approve func(string) bool, journal *replayLog) error {
	return serveGuardedPQ(s, key, backend, in, out, approve, journal, nil)
}
func serveGuardedPQ(s signer, key agreementKey, backend string, in io.Reader, out io.Writer, approve func(string) bool, journal *replayLog, pq *pqKeys, trustedSenders ...*senderTrust) error {
	var e error
	var senders *senderTrust
	if pq!=nil {
		if len(trustedSenders)!=1||trustedSenders[0]==nil{return portableRefusal}
		senders=trustedSenders[0]
	}
	enc := json.NewEncoder(out)
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 4096), 32768)
	var pending *authority
	enrolled := false
	seen := map[[32]byte]bool{}
	fail := reply{Error: "refused"}
	already := func(h [32]byte) bool { return seen[h] || (journal != nil && journal.has(h)) }
	consume := func(h [32]byte) error {
		if already(h) {
			return errors.New("replay")
		}
		if journal != nil {
			if err := journal.consume(h); err != nil {
				return err
			}
		}
		seen[h] = true
		return nil
	}
	for n := 0; scan.Scan(); n++ {
		if n >= maxOps {
			return errors.New("operation budget exhausted")
		}
		r := fail
		var q request
		d := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		d.DisallowUnknownFields()
		err := d.Decode(&q)
		var extra any
		if err != nil || d.Decode(&extra) != io.EOF {
			if e = enc.Encode(r); e != nil {
				return e
			}
			continue
		}
		if pq != nil && q.Op != "public" && q.Op != "pq-public-lab" && q.Op != "pq-proof-lab" && q.Op != "mail-open-hybrid-lab" && q.Op != "mail-seal-hybrid-lab" && q.Op != "close" {
			if e = enc.Encode(fail); e != nil {
				return e
			}
			continue
		}
		if q.Recover&&(pq==nil||(q.Op!="mail-seal-hybrid-lab"&&q.Op!="mail-open-hybrid-lab")){if e=enc.Encode(fail);e!=nil{return e};continue}
		switch q.Op {
		case "pq-public-lab":
			if pq != nil {
				r = reply{OK: true, PQKEM: b64.EncodeToString(pq.kemPub), PQDSA: b64.EncodeToString(pq.dsaPub)}
			}
		case "pq-proof-lab":
			if pq == nil || journal == nil {
				break
			}
			h := replayID("pq-proof-lab", []byte(q.PQChallenge))
			if _, err := decode(q.PQChallenge, 32, 32); err != nil || already(h) {
				break
			}
			if approve("Preuve ML-DSA de laboratoire : " + hex.EncodeToString(h[:])) {
				sig, err := journal.reservePrivateSignature(h, func() ([]byte, error) {
					return pq.proof(q.PQChallenge)
				})
				if err != nil {
					return err
				}
				seen[h] = true
				r = reply{OK: true, PQProof: b64.EncodeToString(sig)}
			}
		case "mail-seal-hybrid-lab":
			if pq==nil||journal==nil||journal.anchor==nil||q.PQContext==nil||q.PQEnvelope!=nil||q.SenderAuth!=nil{break}
			c:=*q.PQContext
			if c.From!=pq.address||c.FromDeviceID!=pq.device||!msgID.MatchString(c.ClientMessageID){break}
			recipient,ok:=senders.contacts[senderKey(c.To,c.ToDeviceID)]
			if !ok||recipient.Expires<=time.Now().UnixMilli(){break}
			if _,err:=recipientKey(recipient);err!=nil{break}
			plain,err:=decode(q.Message,1,maxPlain);if err!=nil{break}
			h:=replayID("mail-outgoing-id-v1",[]byte(c.From+"\x00"+c.FromDeviceID+"\x00"+c.ClientMessageID))
			if (!q.Recover&&already(h))||!json.Valid(plain){clear(plain);break}
			if !approve("Envoi hybride de laboratoire vers "+c.To+" / "+c.ToDeviceID+" / contenu SHA256 "+hexHash(plain)){clear(plain);break}
			if recipient.Expires<=time.Now().UnixMilli(){clear(plain);break}
			if !journal.beginContact(recipient){clear(plain);break}
			reqHash:=recoveryRequest(q)
			result,err:=pq.authorizedMailResult(journal,h,reqHash,q.Recover,func()(reply,error){
				if recipient.Expires<=time.Now().UnixMilli(){return reply{},portableRefusal}
				v,auth,e:=pq.sealOutgoing(s,c,recipient,plain)
				if e!=nil{return reply{},e}
				return reply{OK:true,HybridEnvelope:&v,SenderAuth:&auth},nil
			})
			clear(plain)
			if err==nil&&(result.HybridEnvelope==nil||result.SenderAuth==nil||result.Message!=nil){err=portableRefusal}
			// Recheck the fresh contact policy before releasing either a new
			// result or an explicitly recovered one.
			if err==nil{err=journal.anchor.check(journal.anchorID,len(journal.seen),journal.tail)}
			journal.endContact()
			if err!=nil{if journal.failed{return err};break}
			if recipient.Expires<=time.Now().UnixMilli(){return portableRefusal}
			r=result
		case "mail-open-hybrid-lab":
			if pq == nil || journal == nil || q.PQContext == nil || q.PQEnvelope == nil {
				break
			}
			ctx, err := pq.context(*q.PQContext)
			if err != nil {
				break
			}
			v := q.PQEnvelope
			if !senders.verify(*q.PQContext,*v,q.SenderAuth,time.Now().UnixMilli()){break}
			h := replayID("mail-hybrid-v1", []byte(ctx+"\x00"+v.Ephemeral.X+":"+v.Ephemeral.Y+":"+v.KEM+":"+v.IV+":"+v.Ciphertext))
			if (q.Recover||!already(h)) && approve("Déchiffrement hybride de laboratoire, expéditeur connu : "+q.PQContext.From+" / "+q.PQContext.FromDeviceID+" / "+hex.EncodeToString(h[:])) {
				contact,valid:=senders.contact(*q.PQContext,time.Now().UnixMilli());if !valid||!journal.beginContact(contact){break}
				reqHash:=recoveryRequest(q)
				result,err:=pq.authorizedMailResult(journal,h,reqHash,q.Recover,func()(reply,error){
					if contact.Expires<=time.Now().UnixMilli(){return reply{},portableRefusal}
					plain,e:=pq.open(key,*q.PQContext,*v)
					if e!=nil{return reply{},e}
					msg:=b64.EncodeToString(plain);clear(plain)
					return reply{OK:true,Message:&msg},nil
				})
				if err==nil&&(result.Message==nil||result.HybridEnvelope!=nil||result.SenderAuth!=nil){err=portableRefusal}
				if err==nil{err=journal.anchor.check(journal.anchorID,len(journal.seen),journal.tail)}
				journal.endContact()
				if err!=nil{if journal.failed{return err};break}
				if contact.Expires<=time.Now().UnixMilli(){return portableRefusal}
				r=result
			}

		case "public":
			r = reply{OK: true, Backend: backend, Signing: b64.EncodeToString(elliptic.Marshal(elliptic.P256(), s.Public().X, s.Public().Y)), Encryption: b64.EncodeToString(key.PublicKey().Bytes())}
		case "issue":
			if pending == nil || pending.consumed || time.Since(pending.born) >= 30*time.Second {
				pending, e = issue(s.Public(), time.Now())
				if e == nil {
					c := pending.pending
					r = reply{OK: true, Challenge: &c}
				}
			}
		case "prove":
			if pending != nil && !pending.consumed && q.Challenge != nil && *q.Challenge == pending.pending && time.Since(pending.born) < 30*time.Second && q.Approved && approve("Signature du défi local de test") {
				// Reserve the exact challenge before invoking a private provider.
				// Legacy unanchored laboratory modes retain their existing behavior.
				if journal != nil && journal.anchor != nil {
					raw, err := json.Marshal(q.Challenge)
					if err != nil { return err }
					if err = consume(replayID("prove", raw)); err != nil { return err }
				}
				p, err := approveAndSign(s, *q.Challenge, time.Now(), q.Approved)
				if err == nil && pending.verify(p, time.Now()) {
					r = reply{OK: true, Proof: &p}
				}
			}
		case "enroll-proof":
			enrollID := replayID("enroll", []byte(q.Enrollment))
			if !enrolled && !already(enrollID) && q.Approved && validEnrollment(q.Enrollment, s.Public(), key.PublicKey(), time.Now()) && approve("Inscription de test : "+enrollmentDescription(q.Enrollment)) && validEnrollment(q.Enrollment, s.Public(), key.PublicKey(), time.Now()) {
				h := sha256.Sum256([]byte(q.Enrollment))
				anchored := journal != nil && journal.anchor != nil
				if anchored {
					if err := consume(enrollID); err != nil { return err }
					// A slow quorum must not extend the signed enrollment's TTL.
					if !validEnrollment(q.Enrollment, s.Public(), key.PublicKey(), time.Now()) { break }
				}
				sig, err := s.SignDigest(h)
				if err == nil && len(sig) == 64 {
					if !anchored {
						if err := consume(enrollID); err != nil { return err }
					}
					enrolled = true
					r = reply{OK: true, EnrollmentProof: hex.EncodeToString(sig)}
				}
			}
		case "seal":
			if p, err := public(q.Recipient); err == nil {
				if plain, err := decode(q.Message, 0, maxPlain); err == nil {
					p, err := seal(p, plain)
					clear(plain)
					if err == nil {
						r = reply{OK: true, Packet: &p}
					}
				}
			}
		case "open":
			if q.Packet != nil {
				raw, _ := json.Marshal(q.Packet)
				h := replayID("packet", raw)
				if !already(h) && approve("Déchiffrement de test, empreinte du paquet : "+hex.EncodeToString(h[:])) {
					if plain, err := unseal(key, *q.Packet); err == nil {
						if err := consume(h); err != nil {
							clear(plain)
							return err
						}
						msg := b64.EncodeToString(plain)
						clear(plain)
						r = reply{OK: true, Message: &msg}
					}
				}
			}
		case "mail-open-static-lab":
			// Do not expose this compatibility operation in unanchored or older modes.
			if journal == nil || q.Mail == nil {
				break
			}
			authority, ok := journal.anchor.(*freshQuorum)
			if !ok || !authority.compact || !authority.scheduled {
				break
			}
			h := mailReplay(*q.Mail)
			if !already(h) && approve("Déchiffrement QuanticMail classique de test : "+hex.EncodeToString(h[:])) {
				if plain, err := mailOpen(key, *q.Mail); err == nil {
					if err := consume(h); err != nil {
						clear(plain)
						return err
					}
					msg := b64.EncodeToString(plain)
					clear(plain)
					r = reply{OK: true, Message: &msg}
				}
			}
		case "close":
			return enc.Encode(reply{OK: true})
		}
		if e = enc.Encode(r); e != nil {
			return e
		}
	}
	return scan.Err()
}

var addressRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$`)
var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func publicPin(p any) string {
	b, e := x509.MarshalPKIXPublicKey(p)
	if e != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validEnrollment(raw string, s *ecdsa.PublicKey, e *ecdh.PublicKey, now time.Time) bool {
	if len(raw) > 2048 {
		return false
	}
	var a []json.RawMessage
	if json.Unmarshal([]byte(raw), &a) != nil || len(a) != 11 {
		return false
	}
	var fields [11]string
	for _, i := range []int{0, 1, 2, 4, 5, 6, 7, 8, 9} {
		if json.Unmarshal(a[i], &fields[i]) != nil {
			return false
		}
	}
	var seq, expiry int64
	if json.Unmarshal(a[3], &seq) != nil || json.Unmarshal(a[10], &expiry) != nil {
		return false
	}
	p := e.Bytes()
	if len(p) != 65 {
		return false
	}
	id := sha256.Sum256([]byte("P-256:" + b64.EncodeToString(p[1:33]) + ":" + b64.EncodeToString(p[33:])))
	return fields[0] == "quantic-native-enrollment-lab-v1" && addressRE.MatchString(fields[1]) && hashRE.MatchString(fields[2]) && seq >= 1 && seq < 9007199254740991 && hashRE.MatchString(fields[4]) && fields[5] == "d-"+hex.EncodeToString(id[:16]) && fields[6] == publicPin(s) && fields[7] == publicPin(e) && len(fields[8]) >= 2 && len(fields[8]) <= 192 && strings.TrimSpace(fields[8]) == fields[8] && hashRE.MatchString(fields[9]) && expiry > now.UnixMilli() && expiry-now.UnixMilli() <= 30000
}

func enrollmentDescription(raw string) string {
	var a []json.RawMessage
	if json.Unmarshal([]byte(raw), &a) != nil || len(a) != 11 {
		return "invalid"
	}
	// Display only constrained fields, not attacker-supplied label or control characters.
	var address, device string
	if json.Unmarshal(a[1], &address) != nil || json.Unmarshal(a[5], &device) != nil || !addressRE.MatchString(address) {
		return "invalid"
	}
	return address + " / " + device
}
