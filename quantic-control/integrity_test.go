package control

import (
    "os"
    "path/filepath"
    "testing"
)

func TestBaselineAndScan(t *testing.T) {
    dir := t.TempDir()
    file := filepath.Join(dir, "watched.txt")
    if err := os.WriteFile(file, []byte("original"), 0600); err != nil { t.Fatal(err) }
    m, err := CreateBaseline([]string{file})
    if err != nil { t.Fatal(err) }
    findings, err := Scan(m)
    if err != nil || len(findings) != 1 || findings[0].Status != "unchanged" { t.Fatalf("clean scan: %v %v", findings, err) }
    if err := os.WriteFile(file, []byte("changed"), 0600); err != nil { t.Fatal(err) }
    findings, err = Scan(m)
    if err != nil || findings[0].Status != "changed" { t.Fatalf("modified scan: %v %v", findings, err) }
    if err := os.Remove(file); err != nil { t.Fatal(err) }
    findings, err = Scan(m)
    if err != nil || findings[0].Status != "missing" { t.Fatalf("missing scan: %v %v", findings, err) }
}

func TestBaselineRejectsDuplicatesAndSymlinks(t *testing.T) {
    dir := t.TempDir()
    file := filepath.Join(dir, "file")
    if err := os.WriteFile(file, []byte("x"), 0600); err != nil { t.Fatal(err) }
    if _, err := CreateBaseline([]string{file, file}); err == nil { t.Fatal("duplicate accepted") }
    link := filepath.Join(dir, "link")
    if err := os.Symlink(file, link); err == nil {
        if _, err := CreateBaseline([]string{link}); err == nil { t.Fatal("symlink accepted") }
    }
    if _, err := Scan(Manifest{Version: 1, Files: []Entry{{Path: "relative", SHA256: "bad"}}}); err == nil { t.Fatal("invalid manifest accepted") }
}
