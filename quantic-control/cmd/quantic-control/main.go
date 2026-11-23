package main

import (
    "encoding/json"
    "fmt"
    "io"
    "os"
    "runtime"

    control "github.com/XDSawyerLoL/QuanticMail/quantic-control"
)

func main() {
    if len(os.Args) < 2 { usage(1) }
    switch os.Args[1] {
    case "status":
        printJSON(map[string]any{"product": "Quantic Control Alpha 1", "mode": "local-observation-only", "os": runtime.GOOS, "architecture": runtime.GOARCH, "remoteCommands": false, "autoRemediation": false})
    case "baseline":
        if len(os.Args) < 3 { usage(1) }
        m, err := control.CreateBaseline(os.Args[2:])
        fail(err)
        printJSON(m)
    case "scan":
        if len(os.Args) != 3 { usage(1) }
        f, err := os.Open(os.Args[2])
        fail(err)
        defer f.Close()
        var m control.Manifest
        err = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&m)
        fail(err)
        findings, err := control.Scan(m)
        fail(err)
        printJSON(findings)
        for _, finding := range findings {
            if finding.Status != "unchanged" { os.Exit(2) }
        }
    default:
        usage(1)
    }
}

func usage(code int) {
    fmt.Fprintln(os.Stderr, "Usage: quantic-control status | baseline FILE... | scan BASELINE.json")
    os.Exit(code)
}
func fail(err error) {
    if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
func printJSON(v any) {
    data, err := json.MarshalIndent(v, "", "  ")
    fail(err)
    fmt.Println(string(data))
}
