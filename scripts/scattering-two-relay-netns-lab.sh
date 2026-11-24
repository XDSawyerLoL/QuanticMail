#!/usr/bin/env bash
# Two successive independently keyed lab relays; five namespaces, ONE Linux host.
# All traffic synthetic; not a production protocol.
set -Eeuo pipefail
export SCATTERING_MULTIHOP_RESEAL=1 SCATTERING_MULTIHOP_E2E=1 SCATTERING_MULTIHOP_MIX=1 SCATTERING_MULTIHOP_BATCH_SIZE=8
CHAIN_PROFILE="${SCATTERING_CHAIN_PROFILE:-balanced}"
CHAIN_MIX="${SCATTERING_CHAIN_SECOND_MIX:-1}"
case "$CHAIN_PROFILE" in
 balanced) export SCATTERING_MULTIHOP_B_REAL_CELLS=100 SCATTERING_MULTIHOP_PROFILE=regular;;
 skewed) export SCATTERING_MULTIHOP_B_REAL_CELLS=20 SCATTERING_MULTIHOP_PROFILE=regular;;
 sparse) export SCATTERING_MULTIHOP_B_REAL_CELLS=100 SCATTERING_MULTIHOP_PROFILE=sparse; [[ "$CHAIN_MIX" == 1 ]] || exit 2;;
 *) exit 2;;
esac
[[ "$CHAIN_MIX" == 0 || "$CHAIN_MIX" == 1 ]] || exit 2
export SCATTERING_MULTIHOP_IMPAIRMENT=0 SCATTERING_MULTIHOP_CPU_LOAD=0
if [[ "$#" -ne 1 || ! -x "$1" ]]; then echo 'Usage: bash scripts/scattering-two-relay-netns-lab.sh ABS_GO_PACER' >&2; exit 2; fi
PACER="$(realpath "$1")"
NODE="$(command -v node)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/qs-multihop-XXXXXX")"
NSA="qma-$$"; NSB="qmb-$$"; NSR="qmr-$"; NSD="qmd-$"; NS2="qm2-$"
VAA="qa$$"; VAR="qar$$"; VBB="qb$$"; VBR="qbr$$"; VRD="qrd$$"; VDR="qdr$"; VM1="qm1$"; VM2="qm2$"
CAP_PIDS=(); CHILD_PIDS=(); LOAD_PIDS=()
cleanup(){
 local code=$?
 trap - EXIT
 for p in "${CAP_PIDS[@]}" "${CHILD_PIDS[@]}" "${LOAD_PIDS[@]}"; do
   if [[ -n "$p" ]]; then sudo kill "$p" 2>/dev/null || true; fi
 done
 for ns in "$NSA" "$NSB" "$NSR" "$NS2" "$NSD"; do
   sudo ip netns pids "$ns" 2>/dev/null | while read -r p; do
     [[ -z "$p" ]] || sudo kill "$p" 2>/dev/null || true
   done || true
   sudo ip netns del "$ns" 2>/dev/null || true
 done
 rm -rf -- "$WORK"
 exit "$code"
}
trap cleanup EXIT
for cmd in ip tcpdump timeout; do command -v "$cmd" >/dev/null || exit 2; done
for ns in "$NSA" "$NSB" "$NSR" "$NS2" "$NSD"; do sudo ip netns add "$ns";sudo ip -n "$ns" link set lo up; done
link_pair(){
 local n1="$1" n2="$2" d1="$3" d2="$4" ip1="$5" ip2="$6"
 sudo ip link add "$d1" type veth peer name "$d2"
 sudo ip link set "$d1" netns "$n1"
 sudo ip link set "$d2" netns "$n2"
 sudo ip -n "$n1" addr add "$ip1" dev "$d1"
 sudo ip -n "$n2" addr add "$ip2" dev "$d2"
 sudo ip -n "$n1" link set "$d1" up
 sudo ip -n "$n2" link set "$d2" up
}
link_pair "$NSA" "$NSR" "$VAA" "$VAR" 10.252.41.1/30 10.252.41.2/30
link_pair "$NSB" "$NSR" "$VBB" "$VBR" 10.252.42.1/30 10.252.42.2/30
link_pair "$NSR" "$NS2" "$VM1" "$VM2" 10.252.44.1/30 10.252.44.2/30
link_pair "$NS2" "$NSD" "$VRD" "$VDR" 10.252.43.1/30 10.252.43.2/30
if [[ "${SCATTERING_MULTIHOP_IMPAIRMENT:-0}" == '1' ]]; then
 sudo ip netns exec "$NSR" tc qdisc replace dev "$VRD" root netem delay 25ms 6ms loss 6%
fi
mkdir -p "$WORK/queue" "$WORK/queue2" "$WORK/sender-a" "$WORK/sender-b"
chmod 700 "$WORK/queue" "$WORK/queue2" "$WORK/sender-a" "$WORK/sender-b"
RESEAL="${SCATTERING_MULTIHOP_RESEAL:-0}"
E2E="${SCATTERING_MULTIHOP_E2E:-0}"
MIX="${SCATTERING_MULTIHOP_MIX:-0}"
BATCH="${SCATTERING_MULTIHOP_BATCH_SIZE:-40}"
if [[ "$BATCH" != "8" && "$BATCH" != "20" && "$BATCH" != "40" ]];then
 echo 'unsupported mix batch size' >&2; exit 2
fi
OFFSET="${SCATTERING_MULTIHOP_SOURCE_OFFSET_MS:-0}"
B_REAL="${SCATTERING_MULTIHOP_B_REAL_CELLS:-100}"
if [[ "$B_REAL" != "100" && "$B_REAL" != "20" ]];then echo 'unsupported real-cell mix' >&2;exit 2;fi
if [[ "$B_REAL" == "20" && "$E2E" != "1" ]];then echo 'skew needs E2E lab' >&2;exit 2;fi
A_PRELOAD="140"
B_PRELOAD="140"
EXPECTED_COVER="0"
PROFILE="${SCATTERING_MULTIHOP_PROFILE:-regular}"
FLUSH="0"
if [[ "$B_REAL" == "20" ]];then B_PRELOAD="20";EXPECTED_COVER="80";fi
if [[ "$PROFILE" == "sparse" ]];then
 [[ "$E2E" == "1" && "$MIX" == "1" && "$BATCH" == "8" ]] || exit 2
 A_PRELOAD="3";B_PRELOAD="1";EXPECTED_COVER="196";FLUSH="200"
elif [[ "$PROFILE" != "regular" ]];then exit 2;fi
if [[ "$OFFSET" != "0" && "$OFFSET" != "25" ]];then
 echo 'unsupported source offset' >&2; exit 2
fi
if [[ "$MIX" == "1" && "$E2E" != "1" ]];then echo 'batch-mix requires E2E lab' >&2;exit 2;fi
if [[ "$E2E" == "1" && "$RESEAL" != "1" ]]; then
 echo 'E2E test requires independent hop resealing' >&2; exit 2
fi
if [[ "$RESEAL" == "1" ]]; then
 for name in a b mid out; do
  "$NODE" -e "require('node:fs').writeFileSync(process.argv[1],require('node:crypto').randomBytes(32),{mode:0o600})" "$WORK/$name.key"
 done
fi
if [[ "$E2E" == "1" ]]; then
 # The relay receives only per-hop key paths. Inner key remains endpoint-only.
 "$NODE" -e "require('node:fs').writeFileSync(process.argv[1],require('node:crypto').randomBytes(32),{mode:0o600})" "$WORK/e2e.key"
fi
# Capture binary PCAPs to stdout (opened by unprivileged shell), never as artifacts.
sudo timeout -s INT 19s ip netns exec "$NSR" tcpdump -i "$VAR" -Q in -n -s 256 -U -w - 'udp and dst port 49001' >"$WORK/a.pcap" 2>"$WORK/a.caplog" & CAP_PIDS+=("$!")
sudo timeout -s INT 19s ip netns exec "$NSR" tcpdump -i "$VBR" -Q in -n -s 256 -U -w - 'udp and dst port 49002' >"$WORK/b.pcap" 2>"$WORK/b.caplog" & CAP_PIDS+=("$!")
sudo timeout -s INT 19s ip netns exec "$NSD" tcpdump -i "$VDR" -Q in -n -s 256 -U -w - 'udp and dst port 49003' >"$WORK/out.pcap" 2>"$WORK/out.caplog" & CAP_PIDS+=("$!")
sudo timeout -s INT 19s ip netns exec "$NS2" tcpdump -i "$VM2" -Q in -n -s 256 -U -w - 'udp and dst port 49004' >"$WORK/mid.pcap" 2>"$WORK/mid.caplog" & CAP_PIDS+=("$!")
sleep .8
sudo ip netns exec "$NS2" "$NODE" "$ROOT/scripts/scattering-second-hop-lab.mjs" "$WORK/queue2" "$WORK/mid.key" "$WORK/out.key" "$CHAIN_PROFILE" "$CHAIN_MIX" >"$WORK/relay2.json" 2>"$WORK/relay2.err" &
RELAY2_PID="$!"; CHILD_PIDS+=("$!")
if [[ "$RESEAL" == "1" ]]; then
 sudo ip netns exec "$NSR" "$NODE" "$ROOT/scripts/scattering-hop-reseal-relay-lab.mjs" 10.252.41.2:49001 10.252.42.2:49002 "$WORK/queue" 12 "$WORK/a.key" "$WORK/b.key" "$WORK/mid.key" "$MIX" "$EXPECTED_COVER" "$BATCH" "$FLUSH" >"$WORK/relay.json" 2>"$WORK/relay.err" &
else
 sudo ip netns exec "$NSR" "$NODE" "$ROOT/scripts/scattering-opaque-relay-lab.mjs" 10.252.41.2:49001 10.252.42.2:49002 "$WORK/queue" 12 >"$WORK/relay.json" 2>"$WORK/relay.err" &
fi
RELAY_PID="$!"; CHILD_PIDS+=("$!")
if [[ "$E2E" == "1" ]]; then
 sudo ip netns exec "$NSD" "$NODE" "$ROOT/scripts/scattering-e2e-receiver-lab.mjs" "$PACER" 10.252.43.2 49003 17 "$WORK/out.key" "$WORK/e2e.key" "$PROFILE" >"$WORK/receive.json" 2>"$WORK/receive.err" &
elif [[ "$RESEAL" == "1" ]]; then
 sudo ip netns exec "$NSD" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" receive-synthetic "$PACER" 10.252.43.2 49003 13 "$WORK/out.key" >"$WORK/receive.json" 2>"$WORK/receive.err" &
else
 sudo ip netns exec "$NSD" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" receive "$PACER" 10.252.43.2 49003 13 >"$WORK/receive.json" 2>"$WORK/receive.err" &
fi
RECEIVE_PID="$!"; CHILD_PIDS+=("$!")
sleep 1
sudo ip netns exec "$NS2" "$PACER" -target 10.252.43.2:49003 -queue-dir "$WORK/queue2" -period-us 20000 -poll 10ms -duration 14s >"$WORK/egress.report" 2>"$WORK/egress.err" &
EGRESS_PID="$!"; CHILD_PIDS+=("$!")
sudo ip netns exec "$NSR" "$PACER" -target 10.252.44.2:49004 -queue-dir "$WORK/queue" -period-us 20000 -poll 10ms -duration 11s >"$WORK/mid.report" 2>"$WORK/mid.err" &
MID_PID="$!"; CHILD_PIDS+=("$!")
if [[ "${SCATTERING_MULTIHOP_CPU_LOAD:-0}" == '1' ]]; then
 for _ in 1 2 3 4; do
   sudo timeout 9s ip netns exec "$NSR" sh -c 'while :; do :; done' >/dev/null 2>&1 & LOAD_PIDS+=("$!")
 done
fi
sleep .5
if [[ "$E2E" == "1" ]]; then
 sudo ip netns exec "$NSA" "$NODE" "$ROOT/scripts/scattering-e2e-sender-lab.mjs" "$PACER" 10.252.41.2 49001 5 "$WORK/a.key" "$WORK/e2e.key" 0 "$A_PRELOAD" >"$WORK/a.report" 2>"$WORK/a.err" & PID_A="$!"
 if [[ "$OFFSET" == "25" ]];then sleep .025;fi
 sudo ip netns exec "$NSB" "$NODE" "$ROOT/scripts/scattering-e2e-sender-lab.mjs" "$PACER" 10.252.42.2 49002 5 "$WORK/b.key" "$WORK/e2e.key" 1 "$B_PRELOAD" >"$WORK/b.report" 2>"$WORK/b.err" & PID_B="$!"
elif [[ "$RESEAL" == "1" ]]; then
 sudo ip netns exec "$NSA" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" send-synthetic "$PACER" 10.252.41.2 49001 5 "$WORK/a.key" 50000 >"$WORK/a.report" 2>"$WORK/a.err" & PID_A="$!"
 sudo ip netns exec "$NSB" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" send-synthetic "$PACER" 10.252.42.2 49002 5 "$WORK/b.key" 50000 >"$WORK/b.report" 2>"$WORK/b.err" & PID_B="$!"
else
 sudo ip netns exec "$NSA" "$PACER" -target 10.252.41.2:49001 -queue-dir "$WORK/sender-a" -period-us 50000 -poll 10ms -duration 5s >"$WORK/a.report" 2>"$WORK/a.err" & PID_A="$!"
 sudo ip netns exec "$NSB" "$PACER" -target 10.252.42.2:49002 -queue-dir "$WORK/sender-b" -period-us 50000 -poll 10ms -duration 5s >"$WORK/b.report" 2>"$WORK/b.err" & PID_B="$!"
fi
CHILD_PIDS+=("$PID_A" "$PID_B")
wait "$PID_A" || { cat "$WORK/a.err" >&2;exit 1; }
wait "$PID_B" || { cat "$WORK/b.err" >&2;exit 1; }
for p in "$RELAY_PID" "$MID_PID" "$RELAY2_PID" "$RECEIVE_PID" "$EGRESS_PID"; do
 if ! wait "$p";then
   echo "Lab process failed: $p" >&2
   for f in "$WORK/relay.err" "$WORK/relay2.err" "$WORK/mid.err" "$WORK/receive.err" "$WORK/egress.err"; do cat "$f" >&2; done
   exit 1
 fi
done
for p in "${CAP_PIDS[@]}";do wait "$p" || true; done
"$NODE" "$ROOT/scripts/scattering-two-relay-evidence.mjs" "$WORK" "$CHAIN_PROFILE" "$CHAIN_MIX"
