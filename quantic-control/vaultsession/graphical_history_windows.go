//go:build windows

package vaultsession

import(
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/x509"
 "encoding/hex"
 "encoding/pem"
 "errors"
 "io"
 "os/exec"
 "path/filepath"
 "syscall"
 "time"
 "unsafe"

 control "github.com/XDSawyerLoL/QuanticMail/quantic-control"
 "github.com/XDSawyerLoL/QuanticMail/quantic-control/sentinel"
)

// ParseTrustedEnrollment accepts only public metadata whose exact bytes have
// been pinned independently (not a hash supplied inside that same file).
// It is a lab enrollment package, not a new identity or a trust-on-first-use.
func ParseTrustedEnrollment(raw []byte,expectedSHA256 string)(GraphicalBrokerConfig,error){
 var c GraphicalBrokerConfig
 if len(raw)==0||len(raw)>16384||!pinPattern.MatchString(expectedSHA256){return c,errors.New("independent enrollment fingerprint required")}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=expectedSHA256{return c,errors.New("enrollment fingerprint mismatch")}
 if strictDecode(raw,&c)!=nil{return c,errors.New("invalid enrollment metadata")}
 if _,err:=c.args();err!=nil{return c,err}
 d:=sha256.Sum256(c.Identity.DSAPublicDER)
 if len(c.Identity.DSAPublicDER)!=1974||hex.EncodeToString(d[:])!=c.Identity.DSAPin{return c,errors.New("invalid enrolled ML-DSA key")}
 return c,nil
}
func GraphicalProviderAvailable()bool{return providerAvailable()}

type controllerOutput struct{b []byte}
func(w *controllerOutput)Write(p []byte)(int,error){
 if len(w.b)+len(p)>4096{return 0,errors.New("controller response too large")}
 w.b=append(w.b,p...)
 return len(p),nil
}
func decodeController(raw []byte,pub ed25519.PublicKey)(ed25519.PrivateKey,error){
 block,rest:=pem.Decode(raw)
 if block==nil{return nil,errors.New("controller key invalid")}
 defer clear(block.Bytes)
 if block.Type!="PRIVATE KEY"||len(bytes.TrimSpace(rest))!=0{return nil,errors.New("controller key format invalid")}
 parsed,err:=x509.ParsePKCS8PrivateKey(block.Bytes)
 if err!=nil{return nil,errors.New("controller key invalid")}
 key,ok:=parsed.(ed25519.PrivateKey)
 if !ok||len(key)!=ed25519.PrivateKeySize{return nil,errors.New("controller key type invalid")}
 if !bytes.Equal(key.Public().(ed25519.PublicKey),pub){clear(key);return nil,errors.New("controller does not match enrollment")}
 return key,nil
}
func readExistingController(ctx context.Context,c GraphicalBrokerConfig)(ed25519.PrivateKey,error){
 if _,err:=c.args();err!=nil{return nil,err}
 if err:=safeBrokerPath(c.VaultDirectory);err!=nil{return nil,err}
 pinned,err:=pinGraphicalBroker(c.Binary,c.BinarySHA256);if err!=nil{return nil,err}
 defer pinned.Close()
 ctx,cancel:=context.WithTimeout(ctx,10*time.Second);defer cancel()
 // Reuse the existing Vault helper's private NTFS/ACL and ancestor checks.
 // No new filesystem read API or persistent copy of controller.pem.
 cmd:=exec.CommandContext(ctx,c.Binary,"--windows-client-read-lab",c.VaultDirectory,"controller.pem")
 cmd.Dir=filepath.Dir(c.Binary)
 cmd.SysProcAttr=&syscall.SysProcAttr{HideWindow:true,CreationFlags:0x08000000}
 buf:=make([]uint16,32768)
 n,_,_:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buf[0])),uintptr(len(buf)))
 if n==0||n>=uintptr(len(buf)){return nil,errors.New("system path unavailable")}
 sys:=syscall.UTF16ToString(buf[:n])
 cmd.Env=[]string{"SystemRoot="+filepath.Dir(sys),"WINDIR="+filepath.Dir(sys),"PATH="+sys}
 out:=&controllerOutput{b:make([]byte,0,4096)}
 defer func(){clear(out.b[:cap(out.b)])}()
 cmd.Stdout=out;cmd.Stderr=io.Discard
 if err:=cmd.Run();err!=nil{return nil,errors.New("existing private controller unavailable")}
 return decodeController(out.b,c.Controller)
}

// ReadGraphicalVaultHistory is a single explicit, read-only lab action.
// The GUI caller must obtain separate user consent for reading history.
// The existing classical controller key enters trusted process memory briefly,
// as in the current desktop client; Vault identity private keys/passphrases
// remain inside the Vault. No new persistent key is written.
func ReadGraphicalVaultHistory(ctx context.Context,c GraphicalBrokerConfig,localAuditPath string,limit int)([]sentinel.Record,error){
 if ctx==nil||!providerAvailable(){return nil,errors.New("native PQ provider unavailable")}
 if limit<1||limit>100||!localAbsolute(localAuditPath){return nil,errors.New("invalid local history request")}
 key,err:=readExistingController(ctx,c)
 if err!=nil{return nil,err}
 defer clear(key)
 s,err:=OpenGraphicalBroker(ctx,c,key)
 if err!=nil{return nil,err}
 defer s.Revoke()
 if ctx.Err()!=nil{return nil,ctx.Err()}
 claims,err:=s.AuthorizationClaims("alerts.read",time.Now())
 if err!=nil{return nil,err}
 payload,err:=control.SigningBytes(claims)
 if err!=nil{return nil,err}
 request:=control.SignedRequest{Claims:claims,Signature:ed25519.Sign(key,payload)}
 return s.ReadAuthorizedAlerts(request,localAuditPath,limit)
}
