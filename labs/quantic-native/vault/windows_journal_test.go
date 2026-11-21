//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsProvisionJournalRestart(t *testing.T){
 pub,_,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 controller:=b64.EncodeToString(pub)
 quorum:=strings.Repeat("a",64);addr:="alice~"+strings.Repeat("b",32)+"@quantic"
 dir:=filepath.Join(t.TempDir(),"new")
 pw,pqw:=[]byte("synthetic classical fixture password"),[]byte("different synthetic PQ fixture password")
 result,e:=winProvisionVault(dir,controller,quorum,addr,pw,pqw);if e!=nil{t.Fatal(e)}
 s,a:=result["signingPin"],result["encryptionPin"]
 if _,e=winProvisionVault(dir,controller,quorum,addr,pw,pqw);e==nil{t.Fatal("overwrite")}
 if _,e=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+quorum+"\x00",pw,s,a);e!=nil{t.Fatal(e)}
 binding,e:=pqBinding(s,a,hexHash(pub),quorum,addr,result["deviceId"]);if e!=nil{t.Fatal(e)}
 p,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,addr,result["deviceId"],result["kemPin"],result["dsaPin"]);if e!=nil{t.Fatal(e)};p.close()
 path:=filepath.Join(dir,"journal.log")
 j,e:=winOpenReplay(path,s,a,hexHash(pub));if e!=nil{t.Fatal(e)}
 if j2,e:=winOpenReplay(path,s,a,hexHash(pub));e==nil{j2.close();j.close();t.Fatal("concurrent journal access")}
 j.close()
 cmd:=exec.Command(os.Args[0],"-test.run=^TestWindowsJournalChild$")
 cmd.Env=append(os.Environ(),"QV_WIN_CHILD=1","QV_WIN_JOURNAL="+path,"QV_WIN_SIGN="+s,"QV_WIN_ENC="+a,"QV_WIN_APP="+hexHash(pub))
 // The child flushes a record and exits without closing the journal.
 if out,e:=cmd.CombinedOutput();e!=nil{t.Fatal(e,string(out))}
 j,e=winOpenReplay(path,s,a,hexHash(pub));if e!=nil{t.Fatal(e)}
 k:=replayID("windows-fixture",[]byte("operation"))
 if !j.has(k)||j.consume(k)==nil{j.close();t.Fatal("replay after process exit")}
 j.close()
 if j,e=winOpenReplay(path,s,a,s);e==nil{j.close();t.Fatal("wrong binding")}
 raw,e:=winReadPrivate(path,4096);if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(path,append(raw,1),0600);e!=nil{t.Fatal(e)}
 if j,e=winOpenReplay(path,s,a,hexHash(pub));e==nil{j.close();t.Fatal("partial record accepted")}
}
func TestWindowsJournalChild(t *testing.T){
 if os.Getenv("QV_WIN_CHILD")!="1"{return}
 j,e:=winOpenReplay(os.Getenv("QV_WIN_JOURNAL"),os.Getenv("QV_WIN_SIGN"),os.Getenv("QV_WIN_ENC"),os.Getenv("QV_WIN_APP"));if e!=nil{os.Exit(2)}
 if e=j.consume(replayID("windows-fixture",[]byte("operation")));e!=nil{os.Exit(3)}
 os.Exit(0)
}
func TestWindowsConsoleParsing(t *testing.T){
 b,e:=winConsoleBytes([]uint16{'A',' ', 'B',13,10});if e!=nil||!bytes.Equal(b,[]byte("A B")){t.Fatal(e)}
 for _,line:=range [][]uint16{{'A',10},{'A',0,13,10},{'A',0x100,13,10}}{
  if _,e=winConsoleBytes(line);e==nil{t.Fatal("invalid console text")}
 }
}
