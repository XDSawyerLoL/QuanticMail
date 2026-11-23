package control

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
)

const maxWatchFiles = 128
const maxWatchFileSize = 32 << 20 // 32 MiB per explicitly selected regular file

type Entry struct {
    Path string
    SHA256 string
}

type Manifest struct {
    Version int
    Files []Entry
}

type Finding struct {
    Path string
    Status string // unchanged, changed, missing, inaccessible
}

// CreateBaseline hashes only the files explicitly selected by the local user.
// This is a diagnostic baseline, NOT a signed tamper-proof security database.
func CreateBaseline(paths []string) (Manifest, error) {
    if len(paths) == 0 || len(paths) > maxWatchFiles {
        return Manifest{}, errors.New("select between 1 and 128 paths")
    }
    result := Manifest{Version: 1, Files: make([]Entry, 0, len(paths))}
    unique := make(map[string]bool)
    for _, path := range paths {
        abs, err := filepath.Abs(path)
        if err != nil { return Manifest{}, err }
        abs = filepath.Clean(abs)
        if unique[abs] { return Manifest{}, fmt.Errorf("duplicate path: %s", abs) }
        unique[abs] = true
        digest, err := hashFile(abs)
        if err != nil { return Manifest{}, err }
        result.Files = append(result.Files, Entry{Path: abs, SHA256: digest})
    }
    return result, nil
}

func Scan(m Manifest) ([]Finding, error) {
    if m.Version != 1 || len(m.Files) == 0 || len(m.Files) > maxWatchFiles {
        return nil, errors.New("invalid baseline manifest")
    }
    findings := make([]Finding, 0, len(m.Files))
    for _, entry := range m.Files {
        if !filepath.IsAbs(entry.Path) || len(entry.SHA256) != 64 {
            return nil, errors.New("invalid baseline entry")
        }
        if _, err := hex.DecodeString(entry.SHA256); err != nil {
            return nil, errors.New("invalid hash encoding")
        }
        digest, err := hashFile(entry.Path)
        status := "unchanged"
        if errors.Is(err, os.ErrNotExist) { status = "missing" } else if err != nil { status = "inaccessible" } else if digest != entry.SHA256 { status = "changed" }
        findings = append(findings, Finding{Path: entry.Path, Status: status})
    }
    return findings, nil
}

func hashFile(path string) (string, error) {
    info, err := os.Lstat(path)
    if err != nil { return "", err }
    if !info.Mode().IsRegular() || info.Size() > maxWatchFileSize {
        return "", fmt.Errorf("not an allowed regular file or file too large: %s", path)
    }
    f, err := os.Open(path)
    if err != nil { return "", err }
    defer f.Close()
    opened, err := f.Stat()
    if err != nil { return "", err }
    if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
        return "", errors.New("file changed between inspection and open")
    }
    hash := sha256.New()
    n, err := io.Copy(hash, io.LimitReader(f, maxWatchFileSize+1))
    if err != nil { return "", err }
    if n > maxWatchFileSize { return "", errors.New("file exceeds scan limit") }
    return hex.EncodeToString(hash.Sum(nil)), nil
}
