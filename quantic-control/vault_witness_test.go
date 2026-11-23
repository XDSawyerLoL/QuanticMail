package control

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "net/http"
    "net/http/httptest"
    "os"
    "sync"
    "testing"
    "time"
)

// This mock follows the existing native Vault anchor_server.py /check and
// /advance API, including SHA256(bytes.fromhex(tail+record)). No service
// deployment, privilege elevation or network scan is involved in these tests.
func testIndependentVaultWitness(t *testing.T, id string) (*VaultWitness,func()) {
    t.Helper()
    var mu sync.Mutex
    count,tail:=0,id
    server:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        if r.Method!=http.MethodPost || r.TLS==nil || len(r.TLS.PeerCertificates)==0 {
            http.Error(w,"REFUSED",http.StatusForbidden);return
        }
        var payload map[string]json.RawMessage
        d:=json.NewDecoder(http.MaxBytesReader(w,r.Body,1024))
        if err:=d.Decode(&payload);err!=nil {http.Error(w,"REFUSED",400);return}
        want:=3
        if r.URL.Path=="/advance" {want=4}else if r.URL.Path!="/check" {http.Error(w,"REFUSED",404);return}
        if len(payload)!=want {http.Error(w,"REFUSED",400);return}
        var req struct{ID string `json:"id"`;Count int `json:"count"`;Tail string `json:"tail"`;Record string `json:"record"`}
        b,err:=json.Marshal(payload);if err!=nil{http.Error(w,"REFUSED",400);return}
        if err:=json.Unmarshal(b,&req);err!=nil{http.Error(w,"REFUSED",400);return}
        mu.Lock();defer mu.Unlock()
        if req.ID!=id || req.Count!=count || req.Tail!=tail {http.Error(w,"REFUSED",409);return}
        if r.URL.Path=="/advance" {
            if !validSHA256(req.Record) {http.Error(w,"REFUSED",400);return}
            tBytes,_:=hex.DecodeString(tail);rBytes,_:=hex.DecodeString(req.Record)
            hash:=sha256.Sum256(append(tBytes,rBytes...))
            tail=hex.EncodeToString(hash[:]);count++
        }
        w.WriteHeader(200)
        _,_=w.Write([]byte("OK\n"))
    }))
    server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,ClientAuth:tls.RequireAnyClientCert}
    server.StartTLS()
    leaf:=server.Certificate()
    pin:=sha256.Sum256(leaf.Raw)
    ca:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:leaf.Raw})
    client,err:=NewVaultWitness(VaultWitnessConfig{
        Endpoint:server.URL,ServerCAPEM:ca,ServerCertSHA256:hex.EncodeToString(pin[:]),
        ClientCertificate:server.TLS.Certificates[0],
    })
    if err!=nil{server.Close();t.Fatal(err)}
    return client,server.Close
}

func TestVaultWitnessRejectsUnsafeConnection(t *testing.T) {
    _,err:=NewVaultWitness(VaultWitnessConfig{Endpoint:"http://127.0.0.1:9443"})
    if err==nil{t.Fatal("insecure HTTP allowed")}
    _,err=NewVaultWitness(VaultWitnessConfig{Endpoint:"https://user:pass@127.0.0.1:9443"})
    if err==nil{t.Fatal("URL credentials allowed")}
    id:=sha256.Sum256([]byte("witness-key-test"))
    witness,closeServer:=testIndependentVaultWitness(t,hex.EncodeToString(id[:]))
    defer closeServer()
    if err:=witness.Check(context.Background(),VaultWitnessCursor{ID:hex.EncodeToString(id[:]),Count:0,Tail:hex.EncodeToString(id[:])});err!=nil{t.Fatal(err)}
    if err:=witness.Check(context.Background(),VaultWitnessCursor{ID:hex.EncodeToString(id[:]),Count:1,Tail:hex.EncodeToString(id[:])});err==nil{t.Fatal("wrong witness sequence accepted")}
    if _,err:=witness.Advance(context.Background(),VaultWitnessCursor{},"bad");err==nil{t.Fatal("malformed cursor accepted")}
    bogus:=VaultWitnessCursor{ID:hex.EncodeToString(id[:]),Count:0,Tail:hex.EncodeToString(id[:])}
    if _,err:=witness.Advance(context.Background(),bogus,"bad");err==nil{t.Fatal("invalid digest allowed")}
}

func TestQuanticVaultWitnessDetectsCompleteLocalRollback(t *testing.T) {
    path,keys,operatorPriv:=setupState(t)
    authorityPub,authorityPriv,err:=ed25519.GenerateKey(rand.Reader)
    if err!=nil{t.Fatal(err)}
    seed:=sha256.Sum256([]byte("control-machine-one-independent-witness"))
    id:=hex.EncodeToString(seed[:])
    witness,closeServer:=testIndependentVaultWitness(t,id)
    defer closeServer()
    cursor,err:=InitialVaultWitnessCursor(id)
    if err!=nil{t.Fatal(err)}
    if err:=witness.Check(context.Background(),cursor);err!=nil{t.Fatal(err)}
    d,err:=InitDurableGuard(path,"machine-1",keys)
    if err!=nil{t.Fatal(err)}
    first:=makeSignedAnchor(t,d,"independent-identity-vault",authorityPriv)
    cursor,err=d.AdvancePinnedVaultWitness(context.Background(),witness,first,"independent-identity-vault",authorityPub,cursor)
    if err!=nil{t.Fatal(err)}
    if err:=d.CheckPinnedVaultWitness(context.Background(),witness,first,"independent-identity-vault",authorityPub,cursor);err!=nil{t.Fatal(err)}
    if err:=d.Close();err!=nil{t.Fatal(err)}
    previousJournal,err:=os.ReadFile(path)
    if err!=nil{t.Fatal(err)}
    previousCursor:=cursor
    d,err=OpenDurableGuard(path,"machine-1",keys)
    if err!=nil{t.Fatal(err)}
    now:=time.Now()
    if err:=d.Authorize(request(t,"witness-advance-0001",operatorPriv,now),now);err!=nil{t.Fatal(err)}
    second:=makeSignedAnchor(t,d,"independent-identity-vault",authorityPriv)
    cursor,err=d.AdvancePinnedVaultWitness(context.Background(),witness,second,"independent-identity-vault",authorityPub,cursor)
    if err!=nil{t.Fatal(err)}
    if err:=d.CheckPinnedVaultWitness(context.Background(),witness,second,"independent-identity-vault",authorityPub,cursor);err!=nil{t.Fatal(err)}
    if err:=d.Close();err!=nil{t.Fatal(err)}
    // Local attacker rewinds BOTH the journal and its locally cached signed
    // checkpoint/cursor. The independent witness refuses the older cursor.
    if err:=os.WriteFile(path,previousJournal,0600);err!=nil{t.Fatal(err)}
    oldGuard,err:=OpenPinnedDurableGuard(path,"machine-1",keys,first,"independent-identity-vault",authorityPub)
    if err!=nil{t.Fatal(err)} // Old local signed checkpoint still valid.
    defer oldGuard.Close()
    if err:=oldGuard.CheckPinnedVaultWitness(context.Background(),witness,first,"independent-identity-vault",authorityPub,previousCursor);err==nil{
        t.Fatal("independent vault witness accepted a rolled-back local journal + signed checkpoint")
    }
    if err:=oldGuard.CheckPinnedVaultWitness(context.Background(),nil,first,"independent-identity-vault",authorityPub,previousCursor);err==nil{
        t.Fatal("unavailable witness did not fail closed")
    }
}
