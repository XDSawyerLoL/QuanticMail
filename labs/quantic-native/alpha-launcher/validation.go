package main

// Immutable application pins are embedded by the trusted Windows build AFTER
// the portable package and its SHA256SUMS.txt have been finalized. The GUI
// executable lives OUTSIDE the package to avoid a self-hashing cycle.
import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "bufio"
 "strings"
)

var expectedManifestSHA256 string
var expectedVaultSHA256 string

func validPin(v string) bool {
 if len(v)!=64 { return false }
 for _,r:=range v {
  if !((r>='0'&&r<='9')||(r>='a'&&r<='f')) {return false}
 }
 return true
}

func fileSHA256(p string, limit int64)(string,error){
 st,err:=os.Lstat(p)
 if err!=nil{return "",err}
 if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>limit {return "",errors.New("not a bounded regular file")}
 file,err:=os.Open(p)
 if err!=nil{return "",err}
 defer file.Close()
 h:=sha256.New()
 n,err:=io.Copy(h,io.LimitReader(file,limit+1))
 if err!=nil{return "",err}
 if n!=st.Size()||n>limit{return "",errors.New("file changed while hashing")}
 return hex.EncodeToString(h.Sum(nil)),nil
}

func validateInstallation(root,manifestPin,vaultPin string)error{
 if !validPin(manifestPin)||!validPin(vaultPin){return errors.New("untrusted executable pins")}
 app:=filepath.Join(root,"app")
 st,err:=os.Lstat(app)
 if err!=nil||!st.IsDir()||st.Mode()&os.ModeSymlink!=0{return errors.New("missing application directory")}
 for _,entry:=range []struct{
  name,pin string
  size int64
 }{
  {"SHA256SUMS.txt",manifestPin,262144},
  {filepath.Join("bin","Vault-PQ-lab.exe"),vaultPin,256*1024*1024},
 }{
  actual,err:=fileSHA256(filepath.Join(app,entry.name),entry.size)
  if err!=nil||actual!=entry.pin{return fmt.Errorf("unexpected %s SHA256",entry.name)}
 }
 if err:=validateEntrypointHashes(app);err!=nil{return err}
 // The Windows PowerShell entry point repeats full inventory validation
 // before touching the vault, and the native GUI never has a direct relay
 // fallback or a path to historical user keys.
 for _,name:=range []string{"Start-Windows-PQ-Lab.ps1","Test-Windows-PQ-Package.ps1","Quantic-Sillage-Alpha.ps1"}{
  st,err:=os.Lstat(filepath.Join(app,name))
  if err!=nil||!st.Mode().IsRegular()||st.Size()<=0||st.Size()>1024*1024{
   return fmt.Errorf("missing or unsafe application entry point: %s",name)
  }
 }
 return nil
}

func validateEmbeddedPins()error{
 if !validPin(expectedManifestSHA256)||!validPin(expectedVaultSHA256)||
  strings.EqualFold(expectedManifestSHA256,expectedVaultSHA256){
  return errors.New("release build has no independent package pins")
 }
 return nil
}


// Verify every script executed during startup BEFORE launching PowerShell.
// A pinned manifest alone does not protect a script if its digest is never checked.
func validateEntrypointHashes(app string) error {
 manifest,err:=os.Open(filepath.Join(app,"SHA256SUMS.txt"))
 if err!=nil{return err}
 defer manifest.Close()
 expected:=map[string]string{}
 required:=[]string{"Start-Windows-PQ-Lab.ps1","Test-Windows-PQ-Package.ps1","Quantic-Sillage-Alpha.ps1"}
 scanner:=bufio.NewScanner(io.LimitReader(manifest,262145))
 for scanner.Scan(){
  line:=scanner.Text()
  if len(line)<68 || line[64:68]!=" *./" || !validPin(line[:64]) {return errors.New("invalid package manifest")}
  name:=line[68:]
  for _,requiredName:=range required {
   if name==requiredName {
    if _,exists:=expected[name];exists{return errors.New("duplicate startup script")}
    expected[name]=line[:64]
   }
  }
 }
 if err:=scanner.Err();err!=nil{return err}
 for _,name:=range required {
  pin,ok:=expected[name]
  if !ok{return fmt.Errorf("startup script missing from signed inventory: %s",name)}
  actual,err:=fileSHA256(filepath.Join(app,name),1024*1024)
  if err!=nil||actual!=pin{return fmt.Errorf("startup script integrity failure: %s",name)}
 }
 return nil
}
