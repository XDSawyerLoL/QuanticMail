#!/usr/bin/env bash
# Synthetic-only Linux CI test. Two distinct network namespaces, one physical kernel.
# Passive tcpdump process observes a veth link; no Internet access or account keys.
set -Eeuo pipefail
if [[ "$#" -ne 1 || ! -x "$1" ]]; then
  echo "Usage: bash scripts/scattering-netns-observer-lab.sh ABS_NATIVE_PACER" >&2
  exit 2
fi
PACER="$(realpath "$1")"
NODE="$(command -v node)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/qs-netns-XXXXXX")"
NSA="qsna-$$"
NSB="qsnb-$$"
VETHA="qsa$$"
VETHB="qsb$$"
CAP_PID=""
REC_PID=""
cleanup() {
  local previous=$?
  trap - EXIT
  for pid in "$CAP_PID" "$REC_PID"; do
    if [[ -n "$pid" ]]; then sudo kill "$pid" 2>/dev/null || true; fi
  done
  for ns in "$NSA" "$NSB"; do
    sudo ip netns pids "$ns" 2>/dev/null | while read -r pid; do
      if [[ -n "$pid" ]]; then sudo kill "$pid" 2>/dev/null || true; fi
    done || true
    sudo ip netns del "$ns" 2>/dev/null || true
  done
  rm -rf -- "$WORK"
  exit "$previous"
}
trap cleanup EXIT

for cmd in ip tcpdump timeout; do
  if ! command -v "$cmd" >/dev/null; then
    echo "Missing mandatory network diagnostic tool: $cmd" >&2
    exit 2
  fi
done
sudo ip netns add "$NSA"
sudo ip netns add "$NSB"
sudo ip link add "$VETHA" type veth peer name "$VETHB"
sudo ip link set "$VETHA" netns "$NSA"
sudo ip link set "$VETHB" netns "$NSB"
sudo ip -n "$NSA" addr add 10.251.27.1/30 dev "$VETHA"
sudo ip -n "$NSB" addr add 10.251.27.2/30 dev "$VETHB"
sudo ip -n "$NSA" link set lo up
sudo ip -n "$NSB" link set lo up
sudo ip -n "$NSA" link set "$VETHA" up
sudo ip -n "$NSB" link set "$VETHB" up

one_condition() {
  local mode="$1"
  local sender="send"
  if [[ "$mode" == synthetic ]]; then sender="send-synthetic"; fi
  # Tcpdump has no access to sender's application data or keys.
  sudo timeout -s INT 11s ip netns exec "$NSB" \
    tcpdump -i "$VETHB" -Q in -n -tt -l 'udp and dst port 49001' \
    >"$WORK/$mode.capture" 2>"$WORK/$mode.capture.stderr" &
  CAP_PID="$!"
  sleep 0.8
  if ! kill -0 "$CAP_PID" 2>/dev/null; then
    cat "$WORK/$mode.capture.stderr" >&2
    echo "Passive observer did not start" >&2
    return 1
  fi
  sudo ip netns exec "$NSB" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" \
    receive "$PACER" 10.251.27.2 49001 10 \
    >"$WORK/$mode.receiver" 2>&1 &
  REC_PID="$!"
  sleep 1.2
  sudo ip netns exec "$NSA" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" \
    "$sender" "$PACER" 10.251.27.2 49001 6 >"$WORK/$mode.sender" 2>&1 || {
      cat "$WORK/$mode.sender" >&2; return 1;
    }
  wait "$REC_PID" || { cat "$WORK/$mode.receiver" >&2; return 1; }
  REC_PID=""
  wait "$CAP_PID" || true  # timeout exits 124 after interrupting tcpdump.
  CAP_PID=""
  if [[ ! -s "$WORK/$mode.capture" ]]; then
    cat "$WORK/$mode.capture.stderr" >&2
    echo "No external veth capture" >&2
    return 1
  fi
}
one_condition cover
one_condition synthetic
"$NODE" --input-type=module - "$ROOT" "$WORK" <<'NODE'
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
const [root,work]=process.argv.slice(2);
const {analyzeNamespacePairPaths}=await import(pathToFileURL(resolve(root,'lib/quantic/scattering-netns-evidence.mjs')).href);
const r=analyzeNamespacePairPaths([
  resolve(work,'cover.capture'),resolve(work,'cover.sender'),resolve(work,'cover.receiver'),
  resolve(work,'synthetic.capture'),resolve(work,'synthetic.sender'),resolve(work,'synthetic.receiver'),
]);
console.log(JSON.stringify(r,null,2));
NODE
