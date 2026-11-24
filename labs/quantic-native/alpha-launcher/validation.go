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
 // Verify the actual script bytes against the pinned inventory BEFORE
 // executing any script, including the inventory verifier itself.
 return validateStartupScripts(app,manifestPin)
}
func validateStartupScripts(app,pin string)error{
 path:=filepath.Join(app,"SHA256SUMS.txt")
 st,e:=os.Lstat(path);if e!=nil||!st.Mode().IsRegular()||st.Size()<1||st.Size()>262144{return errors.New("unsafe startup manifest")}
 f,e:=os.Open(path);if e!=nil{return e};defer f.Close()
 raw,e:=io.ReadAll(io.LimitReader(f,262145));if e!=nil||int64(len(raw))!=st.Size()||len(raw)>262144{return errors.New("startup manifest changed")}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=pin{return errors.New("startup manifest pin mismatch")}
 names:=[]string{"Start-Windows-PQ-Lab.ps1","Test-Windows-PQ-Package.ps1","Quantic-Sillage-Alpha.ps1"}
 expected:=map[string]string{}
 for _,line:=range strings.Split(strings.TrimSuffix(string(raw),"\n"),"\n"){
  line=strings.TrimSuffix(line,"\r")
  if len(line)<69||line[64:68]!=" *./"||!validPin(line[:64]){return errors.New("invalid startup manifest entry")}
  for _,name:=range names {
   if strings.EqualFold(line[68:],name){
    if line[68:]!=name||expected[name]!=""{return errors.New("ambiguous startup script entry")}
    expected[name]=line[:64]
   }
  }
 }
 for _,name:=range names{
  if !validPin(expected[name]){return fmt.Errorf("startup script not inventoried: %s",name)}
  actual,e:=fileSHA256(filepath.Join(app,name),1024*1024)
  if e!=nil||actual!=expected[name]{return fmt.Errorf("startup script integrity refused: %s",name)}
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
