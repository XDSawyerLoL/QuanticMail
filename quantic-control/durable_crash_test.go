package control

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "os"
    "os/exec"
    "path/filepath"
    "testing"
    "time"
)

func TestCrashRecoveryAfterSuccessfulFsync(t *testing.T) {
    path, keys, priv := setupState(t)
    now := time.Now()
    initial, err := InitDurableGuard(path, "machine-1", keys)
    if err != nil { t.Fatal(err) }
    if err := initial.Close(); err != nil { t.Fatal(err) }
    req := request(t, "crash-test-nonce-12345", priv, now)
    payload, err := json.Marshal(req)
    if err != nil { t.Fatal(err) }
    if os.Getenv("QUANTIC_DURABLE_CRASH_CHILD") == "yes" {
        t.Fatal("unexpected child branch")
    }
    exe, err := os.Executable()
    if err != nil { t.Fatal(err) }
    cmd := exec.Command(exe, "-test.run=^TestDurableCrashChild$")
    cmd.Env = append(os.Environ(),
        "QUANTIC_DURABLE_CRASH_CHILD=yes",
        "QUANTIC_DURABLE_PATH="+path,
        "QUANTIC_DURABLE_PUB="+base64.StdEncoding.EncodeToString(keys["admin"]),
        "QUANTIC_DURABLE_REQUEST="+base64.StdEncoding.EncodeToString(payload))
    output, err := cmd.CombinedOutput()
    if err == nil { t.Fatalf("child should exit non-zero to simulate process crash: %s", output) }
    if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode()!=73 {
        t.Fatalf("child failed before crash simulation: %v %s", err, output)
    }
    reopened, err := OpenDurableGuard(path, "machine-1", keys)
    if err != nil { t.Fatalf("cannot restart after abrupt exit: %v", err) }
    defer reopened.Close()
    if err := reopened.Authorize(req, now); err == nil { t.Fatal("a successfully fsynced request was replayed after crash") }
    if _, err := os.Stat(filepath.Dir(path)); err != nil { t.Fatal(err) }
}

func TestDurableCrashChild(t *testing.T) {
    if os.Getenv("QUANTIC_DURABLE_CRASH_CHILD") != "yes" { return }
    pub, err := base64.StdEncoding.DecodeString(os.Getenv("QUANTIC_DURABLE_PUB"))
    if err != nil { os.Exit(70) }
    payload, err := base64.StdEncoding.DecodeString(os.Getenv("QUANTIC_DURABLE_REQUEST"))
    if err != nil { os.Exit(70) }
    var req SignedRequest
    if err := json.Unmarshal(payload, &req); err != nil { os.Exit(70) }
    g, err := OpenDurableGuard(os.Getenv("QUANTIC_DURABLE_PATH"), "machine-1", map[string]ed25519.PublicKey{"admin":pub})
    if err != nil { os.Exit(71) }
    if err := g.Authorize(req, time.Unix(req.Claims.IssuedAt, 0)); err != nil { os.Exit(72) }
    // Deliberately bypass Close(): proves the OS lock is released on exit
    // while the fsynced replay protection survives.
    os.Exit(73)
}
