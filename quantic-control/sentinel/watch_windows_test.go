//go:build windows

package sentinel

import(
    "context"
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestNativeWindowsDirectoryChanges(t *testing.T){
    root:=t.TempDir()
    events:=make(chan Event,64)
    ctx,cancel:=context.WithCancel(context.Background())
    done:=make(chan error,1)
    go func(){done<-Watch(ctx,root,events)}()
    time.Sleep(350*time.Millisecond)
    target:=filepath.Join(root,"quantic-control-test.txt")
    if err:=os.WriteFile(target,[]byte("sample only"),0600);err!=nil{cancel();t.Fatal(err)}
    deadline:=time.After(8*time.Second)
    received:=false
    for !received{
        select{
        case ev:=<-events:
            if ev.Path==target&&(ev.Kind==Created||ev.Kind==Written){received=true}
        case err:=<-done:
            cancel()
            t.Fatalf("watcher stopped before reporting file: %v",err)
        case <-deadline:
            cancel()
            select{
            case err:=<-done:t.Logf("watcher after cancel: %v",err)
            case <-time.After(3*time.Second):t.Log("watcher did not stop after cancel")
            }
            t.Fatal("Windows failed to report file modification")
        }
    }
    cancel()
    select{
    case err:=<-done:if err!=nil{t.Fatalf("watcher shutdown: %v",err)}
    case <-time.After(5*time.Second):t.Fatal("native watcher failed to stop after cancellation")
    }
}
