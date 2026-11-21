package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Separate authority, operated outside the vault's rollback domain. TLS 1.3,
// exact server certificate pin, mutual authentication. No automatic recovery.
type anchorConfig struct {
	URL        string `json:"url"`
	ServerCA   string `json:"serverCA"`
	ServerPin  string `json:"serverPin"`
	ClientCert string `json:"clientCert"`
	ClientKey  string `json:"clientKey"`
}
type anchorRequest struct {
	ID        string `json:"id"`
	Count     int    `json:"count"`
	Tail      string `json:"tail"`
	Record    string `json:"record,omitempty"`
	PQBinding string `json:"pqBinding,omitempty"`
	ContactID string `json:"contactId,omitempty"`
	ContactCommitment string `json:"contactCommitment,omitempty"`
}
type checkpointAnchor interface {
	check(id string, count int, tail [32]byte) error
	advance(id string, count int, tail, record [32]byte) error
}
type remoteAnchor struct {
	endpoint  string
	serverPin string
	client    *http.Client
}

func newRemoteAnchor(path string) (*remoteAnchor, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var c anchorConfig
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&c) != nil || d.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid anchor config")
	}
	return remoteFromConfig(c)
}
func remoteFromConfig(c anchorConfig) (*remoteAnchor, error) {
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !hashRE.MatchString(c.ServerPin) {
		return nil, errors.New("invalid anchor endpoint or pin")
	}
	ca, e := os.ReadFile(c.ServerCA)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid authority CA")
	}
	cert, e := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || hexHash(cs.PeerCertificates[0].Raw) != c.ServerPin {
			return errors.New("anchor server pin mismatch")
		}
		return nil
	}}, DisableCompression: true, ResponseHeaderTimeout: 3 * time.Second}
	return &remoteAnchor{c.URL, c.ServerPin, &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("anchor redirect refused") }}}, nil
}
func (a *remoteAnchor) call(op string, p anchorRequest) error {
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	resp, e := a.client.Post(a.endpoint+"/"+op, "application/json", bytes.NewReader(b))
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 128))
	if e != nil || resp.StatusCode != 200 || string(raw) != "OK\n" {
		return errors.New("independent checkpoint refused")
	}
	return nil
}
func (a *remoteAnchor) check(id string, count int, tail [32]byte) error {
	return a.call("check", anchorRequest{ID: id, Count: count, Tail: hex.EncodeToString(tail[:])})
}
func (a *remoteAnchor) advance(id string, count int, tail, record [32]byte) error {
	return a.call("advance", anchorRequest{ID: id, Count: count, Tail: hex.EncodeToString(tail[:]), Record: hex.EncodeToString(record[:])})
}
func (j *replayLog) attachAnchor(a checkpointAnchor, id string) error {
	if a == nil || !hashRE.MatchString(id) {
		return errors.New("invalid checkpoint")
	}
	if e := a.check(id, len(j.seen), j.tail); e != nil {
		return e
	}
	j.anchor = a
	j.anchorID = id
	return nil
}
func anchorID(sign, enc, app string) (string, error) {
	h, e := replayBinding(sign, enc, app)
	if e != nil {
		return "", e
	}
	v := sha256.Sum256(h)
	return hex.EncodeToString(v[:]), nil
}
