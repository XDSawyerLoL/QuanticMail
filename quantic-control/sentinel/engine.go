// Package sentinel implements a deliberately limited, user-initiated machine
// activity observer. It reports potentially destructive bursts but does not
// attribute events to processes, terminate tasks, or claim to stop malware.
package sentinel

import (
    "path/filepath"
    "strings"
    "sync"
    "time"
)

type Kind string
const (
    Created Kind = "created"
    Written Kind = "written"
    Removed Kind = "removed"
    Renamed Kind = "renamed"
    Overflow Kind = "overflow"
)
type Event struct { Path string; Kind Kind; At time.Time }
type Alert struct {Time time.Time;Level string;Rule string;Count int;UniqueFiles int;Example string}
type Policy struct {Window time.Duration;Cooldown time.Duration;BurstFiles int;DestructiveFiles int;SuspiciousFiles int}
func DefaultPolicy() Policy {
    return Policy{Window:15*time.Second,Cooldown:30*time.Second,BurstFiles:20,DestructiveFiles:8,SuspiciousFiles:4}
}
type Detector struct {mu sync.Mutex;policy Policy;recent []Event;lastAlert time.Time}
func NewDetector(p Policy)*Detector{
    d:=DefaultPolicy()
    if p.Window>0&&p.Window<=time.Minute{d.Window=p.Window}
    if p.Cooldown>0&&p.Cooldown<=10*time.Minute{d.Cooldown=p.Cooldown}
    if p.BurstFiles>=5{d.BurstFiles=p.BurstFiles}
    if p.DestructiveFiles>=3{d.DestructiveFiles=p.DestructiveFiles}
    if p.SuspiciousFiles>=2{d.SuspiciousFiles=p.SuspiciousFiles}
    return &Detector{policy:d}
}
var suspiciousSuffixes=map[string]bool{
    ".locked":true,".encrypted":true,".locky":true,".wncry":true,
    ".ryk":true,".crypt":true,".encryptedfile":true,
}
// Observe computes aggregate, rate-limited alerts without reading file data.
// Event overflows are reported because monitoring coverage was lost.
func(d *Detector) Observe(e Event)*Alert{
    d.mu.Lock();defer d.mu.Unlock()
    if e.At.IsZero(){e.At=time.Now()}
    if e.Kind==Overflow{
        if !d.lastAlert.IsZero()&&e.At.Sub(d.lastAlert)<d.policy.Cooldown{return nil}
        d.lastAlert=e.At
        return &Alert{Time:e.At,Level:"warning",Rule:"Événements perdus : surveillance incomplète"}
    }
    if e.Path==""{return nil}
    cutoff:=e.At.Add(-d.policy.Window)
    kept:=d.recent[:0]
    for _,x:=range d.recent{if !x.At.Before(cutoff){kept=append(kept,x)}}
    d.recent=append(kept,e)
    if len(d.recent)>4096{d.recent=d.recent[len(d.recent)-4096:]}
    unique,destructive,suspicious:=map[string]bool{},map[string]bool{},map[string]bool{}
    for _,x:=range d.recent{
        path:=strings.ToLower(filepath.Clean(x.Path))
        unique[path]=true
        if x.Kind==Removed||x.Kind==Renamed{destructive[path]=true}
        if (x.Kind==Renamed||x.Kind==Created)&&suspiciousSuffixes[strings.ToLower(filepath.Ext(path))]{suspicious[path]=true}
    }
    rule,level:="",""
    switch{
    case len(destructive)>=d.policy.DestructiveFiles:rule,level="Suppressions ou renommages rapides sur plusieurs fichiers","high"
    case len(suspicious)>=d.policy.SuspiciousFiles:rule,level="Extensions suspectes apparues rapidement","high"
    case len(unique)>=d.policy.BurstFiles:rule,level="Modifications rapides sur de nombreux fichiers","warning"
    }
    if rule==""||(!d.lastAlert.IsZero()&&e.At.Sub(d.lastAlert)<d.policy.Cooldown){return nil}
    d.lastAlert=e.At
    return &Alert{Time:e.At,Level:level,Rule:rule,Count:len(d.recent),UniqueFiles:len(unique),Example:e.Path}
}
