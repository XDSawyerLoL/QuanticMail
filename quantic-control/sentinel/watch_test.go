package sentinel

import(
    "context"
    "os"
    "path/filepath"
    "testing"
    "time"
)
func TestContinuousWatcherReportsCreate(t *testing.T){
    dir:=t.TempDir()
    events:=make(chan Event,128)
    ctx,cancel:=context.WithCancel(context.Background())
    done:=make(chan error,1)
    go func(){done<-Watch(ctx,dir,events)}()
    defer func(){
        cancel()
        select{case <-done:case <-time.After(4*time.Second):t.Error("watcher did not stop")}
    }()
    time.Sleep(200*time.Millisecond)
    file:=filepath.Join(dir,"safe-sample.txt")
    if err:=os.WriteFile(file,[]byte("v1"),0600);err!=nil{t.Fatal(err)}
    timer:=time.NewTimer(6*time.Second);defer timer.Stop()
    for{
        select{
        case ev:=<-events:if ev.Path==file&&ev.Kind==Created{return}
        case err:=<-done:t.Fatalf("watcher stopped early: %v",err)
        case <-timer.C:t.Fatal("periodic monitoring did not detect a new file")
        }
    }
}
func TestSnapshotDetectsChangedAndRemovedFiles(t *testing.T){
    root:=t.TempDir();path:=filepath.Join(root,"file.txt")
    if err:=os.WriteFile(path,[]byte("first"),0600);err!=nil{t.Fatal(err)}
    a,err:=snapshot(root);if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(path,[]byte("changed-more"),0600);err!=nil{t.Fatal(err)}
    b,err:=snapshot(root);if err!=nil{t.Fatal(err)}
    if a[path]==b[path]{t.Fatal("modified file metadata not changed")}
    if err:=os.Remove(path);err!=nil{t.Fatal(err)}
    c,err:=snapshot(root);if err!=nil{t.Fatal(err)}
    if _,ok:=c[path];ok{t.Fatal("removed file remains in snapshot")}
}
func TestWatcherDoesNotModifyContent(t *testing.T){
    dir:=t.TempDir();file:=filepath.Join(dir,"original.txt")
    if err:=os.WriteFile(file,[]byte("safe"),0600);err!=nil{t.Fatal(err)}
    if _,err:=snapshot(dir);err!=nil{t.Fatal(err)}
    b,err:=os.ReadFile(file);if err!=nil{t.Fatal(err)}
    if string(b)!="safe"{t.Fatal("monitor mutated file")}
}
