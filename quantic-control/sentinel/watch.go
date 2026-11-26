package sentinel

import (
    "context"
    "errors"
    "fmt"
    "io/fs"
    "os"
    "path/filepath"
    "sort"
    "time"
)
const maxDirectoryEntries=5000
const scanInterval=2*time.Second
type entryStamp struct{size int64;mtime int64}

// snapshot reads bounded regular-file metadata, not file contents. Symlinks
// are not followed. An incomplete or excessively large scan is an error.
func snapshot(root string)(map[string]entryStamp,error){
    result:=make(map[string]entryStamp)
    n:=0
    err:=filepath.WalkDir(root,func(path string,entry fs.DirEntry,walkErr error)error{
        if walkErr!=nil{return walkErr}
        n++
        if n>maxDirectoryEntries{return fmt.Errorf("dossier trop volumineux (maximum %d entrées)",maxDirectoryEntries)}
        if entry.Type()&os.ModeSymlink!=0{return nil}
        if entry.IsDir(){return nil}
        info,err:=entry.Info()
        if err!=nil{return err}
        if !info.Mode().IsRegular(){return nil}
        result[path]=entryStamp{size:info.Size(),mtime:info.ModTime().UnixNano()}
        return nil
    })
    return result,err
}

// Watch checks a user-selected folder every two seconds. This is a periodic
// metadata scan, NOT a real-time kernel notification stream. It can miss
// activity created and reverted between two scans. It never modifies files.
func Watch(ctx context.Context,root string,out chan<-Event)error{
    if out==nil{return errors.New("event receiver required")}
    if !filepath.IsAbs(root){return errors.New("absolute directory required")}
    root=filepath.Clean(root)
    info,err:=os.Lstat(root)
    if err!=nil{return err}
    if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("a real local directory is required")}
    prior,err:=snapshot(root)
    if err!=nil{return fmt.Errorf("unable to establish monitoring baseline: %w",err)}
    ticker:=time.NewTicker(scanInterval)
    defer ticker.Stop()
    send:=func(e Event)error{
        select{case out<-e:return nil;case <-ctx.Done():return ctx.Err()}
    }
    for{
        select{
        case <-ctx.Done():return nil
        case now:=<-ticker.C:
            current,err:=snapshot(root)
            if err!=nil{return fmt.Errorf("monitoring stopped (incomplete view): %w",err)}
            names:=make([]string,0,len(current)+len(prior))
            seen:=make(map[string]bool,len(current)+len(prior))
            for name:=range current{names=append(names,name);seen[name]=true}
            for name:=range prior{if !seen[name]{names=append(names,name)}}
            sort.Strings(names)
            for _,name:=range names{
                cur,yes:=current[name];old,was:=prior[name]
                var kind Kind
                switch{
                case yes&&!was:kind=Created
                case was&&!yes:kind=Removed
                case was&&yes&&cur!=old:kind=Written
                default:continue
                }
                if err:=send(Event{Path:name,Kind:kind,At:now});err!=nil{return nil}
            }
            prior=current
        }
    }
}
