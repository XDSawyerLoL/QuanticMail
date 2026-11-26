package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

func pqCLI(args []string) (bool, error) {
	if len(args) == 9 && args[1] == "--provision-pq-sidecar-lab" { // path sign enc app quorum address device
		app, e := appPublic(args[5])
		if e != nil {
			return true, e
		}
		magic, e := pqBinding(args[3], args[4], hexHash(app), args[6], args[7], args[8])
		if e != nil {
			return true, e
		}
		pw, e := localSecret("Nouveau coffre PQ de laboratoire : ")
		if e != nil {
			return true, e
		}
		defer clear(pw)
		confirm, e := localSecret("Confirmer la phrase secrète : ")
		if e != nil {
			return true, e
		}
		defer clear(confirm)
		if !equalSecret(pw, confirm) {
			return true, portableRefusal
		}
		k, e := pqGenerate("ML-KEM-768")
		if e != nil {
			return true, e
		}
		defer k.close()
		d, e := pqGenerate("ML-DSA-65")
		if e != nil {
			return true, e
		}
		defer d.close()
		p, e := pqMake(k, d, args[7], args[8])
		if e != nil {
			return true, e
		}
		if e = pqWrite(args[2], magic, pw, p); e != nil {
			return true, e
		}
		return true, json.NewEncoder(os.Stdout).Encode(map[string]string{"kemPin": p.kemPin, "dsaPin": p.dsaPin, "kemPublic": b64.EncodeToString(p.kemPub), "dsaPublic": b64.EncodeToString(p.dsaPub)})
	}
	if len(args) > 1 && args[1] == "--broker-software-pq-quorum-lab" {
		if len(args) != 16 || !hashRE.MatchString(args[13]) {
			return true, portableRefusal
		}
		// Compact arguments plus sidecar, address, device, two PQ pins, independent dual root pin.
		q, e := newQuorumAnchor(args[7])
		if e != nil {
			return true, e
		}
		a := &freshQuorum{q: q, scheduled: true, compact: true}
		pub, e := appPublic(args[5])
		if e != nil {
			return true, e
		}
		if filepath.Dir(args[2]) != filepath.Dir(args[6]) || filepath.Dir(args[2]) != filepath.Dir(args[8]) {
			return true, portableRefusal
		}
		magic, e := pqBinding(args[3], args[4], hexHash(pub), q.pin, args[9], args[10])
		if e != nil {
			return true, e
		}
		pw, e := localSecret("Ouvrir le coffre classique de laboratoire : ")
		if e != nil {
			return true, e
		}
		defer clear(pw)
		k, e := openSoftwareMode(args[2], pw, args[3], args[4], anchoredMagic+"compact-manifest-quorum:"+q.pin+"\x00")
		clear(pw)
		if e != nil {
			return true, e
		}
		p := k.agreement.PublicKey().Bytes()
		if args[10] != "d-"+hexHash([]byte("P-256:" + b64.EncodeToString(p[1:33]) + ":" + b64.EncodeToString(p[33:])))[:32] {
			return true, portableRefusal
		}
		pw2, e := localSecret("Ouvrir le coffre PQ de laboratoire : ")
		if e != nil {
			return true, e
		}
		defer clear(pw2)
		pq, e := pqRead(args[8], magic, pw2, args[9], args[10], args[11], args[12])
		clear(pw2)
		if e != nil {
			return true, e
		}
		defer pq.close()
		a.dualRootPin, a.pqAddress, a.pqDevice = args[13], pq.address, pq.device
		a.pqKemPin, a.pqDsaPin = pq.kemPin, pq.dsaPin
		a.pqBinding = hexHash([]byte("quantic-pq-key-binding-lab/v1\x00" + pq.address + "\x00" + pq.device + "\x00" + pq.kemPin + pq.dsaPin))
		info, e := os.Lstat(args[6])
		if e != nil || !info.Mode().IsRegular() || !privatePortableFile(info) {
			return true, portableRefusal
		}
		j, e := openReplay(args[6], args[3], args[4], hexHash(pub))
		if e != nil {
			return true, e
		}
		defer j.close()
		id, e := anchorID(args[3], args[4], hexHash(pub))
		if e != nil {
			return true, e
		}
		var proof *dualLocalProof
		if args[14]=="auto" {
			proof,e=a.fetchDualLocalProof(id,len(j.seen),j.tail)
		} else {
			proof,e=a.loadDualLocalProof(args[14],id)
		}
		if e != nil { return true, e }
		a.localProof = proof
		senders,e:=loadSenderTrust(args[15]);if e!=nil{return true,e}
		if e = j.attachAnchor(a, id); e != nil {
			return true, e
		}
		return true, authenticateFrames(pub, os.Stdin, os.Stdout, func(in io.Reader, out io.Writer) error {
			return serveGuardedPQ(softwareSigner{k.signing}, k.agreement, "software-pq-quorum-lab", in, out, localPortableApproval, j, pq, senders)
		})
	}
	return false, nil
}
