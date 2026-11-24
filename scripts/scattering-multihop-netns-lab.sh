#!/usr/bin/env bash
# Research-only negative control: 2 native senders -> opaque relay -> native egress.
# FOUR namespaces, ONE physical Linux kernel; never use real identities/messages.
set -Eeuo pipefail
if [[ "$#" -ne 1 || ! -x "$1" ]]; then echo 'Usage: bash scripts/scattering-multihop-netns-lab.sh ABS_GO_PACER' >&2; exit 2; fi
PACER="$(realpath "$1")"
NODE="$(command -v node)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/qs-multihop-XXXXXX")"
NSA="qma-$$"; NSB="qmb-$$"; NSR="qmr-$$"; NSD="qmd-$$"
VAA="qa$$"; VAR="qar$$"; VBB="qb$$"; VBR="qbr$$"; VRD="qrd$$"; VDR="qdr$$"
CAP_PIDS=(); CHILD_PIDS=(); LOAD_PIDS=()
cleanup(){
 local code=$?
 trap - EXIT
 for p in "${CAP_PIDS[@]}" "${CHILD_PIDS[@]}" "${LOAD_PIDS[@]}"; do
   if [[ -n "$p" ]]; then sudo kill "$p" 2>/dev/null || true; fi
 done
 for ns in "$NSA" "$NSB" "$NSR" "$NSD"; do
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
for ns in "$NSA" "$NSB" "$NSR" "$NSD"; do sudo ip netns add "$ns";sudo ip -n "$ns" link set lo up; done
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
link_pair "$NSR" "$NSD" "$VRD" "$VDR" 10.252.43.1/30 10.252.43.2/30
if [[ "${SCATTERING_MULTIHOP_IMPAIRMENT:-0}" == '1' ]]; then
 sudo ip netns exec "$NSR" tc qdisc replace dev "$VRD" root netem delay 25ms 6ms loss 6%
fi
mkdir -p "$WORK/queue" "$WORK/sender-a" "$WORK/sender-b"
chmod 700 "$WORK/queue" "$WORK/sender-a" "$WORK/sender-b"
RESEAL="${SCATTERING_MULTIHOP_RESEAL:-0}"
if [[ "$RESEAL" == "1" ]]; then
 for name in a b out; do
  "$NODE" -e "require('node:fs').writeFileSync(process.argv[1],require('node:crypto').randomBytes(32),{mode:0o600})" "$WORK/$name.key"
 done
fi
# Capture binary PCAPs to stdout (opened by unprivileged shell), never as artifacts.
sudo timeout -s INT 17s ip netns exec "$NSR" tcpdump -i "$VAR" -Q in -n -s 256 -U -w - 'udp and dst port 49001' >"$WORK/a.pcap" 2>"$WORK/a.caplog" & CAP_PIDS+=("$!")
sudo timeout -s INT 17s ip netns exec "$NSR" tcpdump -i "$VBR" -Q in -n -s 256 -U -w - 'udp and dst port 49002' >"$WORK/b.pcap" 2>"$WORK/b.caplog" & CAP_PIDS+=("$!")
sudo timeout -s INT 17s ip netns exec "$NSD" tcpdump -i "$VDR" -Q in -n -s 256 -U -w - 'udp and dst port 49003' >"$WORK/out.pcap" 2>"$WORK/out.caplog" & CAP_PIDS+=("$!")
sleep .8
if [[ "$RESEAL" == "1" ]]; then
 sudo ip netns exec "$NSR" "$NODE" "$ROOT/scripts/scattering-hop-reseal-relay-lab.mjs" 10.252.41.2:49001 10.252.42.2:49002 "$WORK/queue" 12 "$WORK/a.key" "$WORK/b.key" "$WORK/out.key" >"$WORK/relay.json" 2>"$WORK/relay.err" &
else
 sudo ip netns exec "$NSR" "$NODE" "$ROOT/scripts/scattering-opaque-relay-lab.mjs" 10.252.41.2:49001 10.252.42.2:49002 "$WORK/queue" 12 >"$WORK/relay.json" 2>"$WORK/relay.err" &
fi
RELAY_PID="$!"; CHILD_PIDS+=("$!")
if [[ "$RESEAL" == "1" ]]; then
 sudo ip netns exec "$NSD" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" receive-synthetic "$PACER" 10.252.43.2 49003 13 "$WORK/out.key" >"$WORK/receive.json" 2>"$WORK/receive.err" &
else
 sudo ip netns exec "$NSD" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" receive "$PACER" 10.252.43.2 49003 13 >"$WORK/receive.json" 2>"$WORK/receive.err" &
fi
RECEIVE_PID="$!"; CHILD_PIDS+=("$!")
sleep 1
sudo ip netns exec "$NSR" "$PACER" -target 10.252.43.2:49003 -queue-dir "$WORK/queue" -period-us 20000 -poll 10ms -duration 11s >"$WORK/egress.report" 2>"$WORK/egress.err" &
EGRESS_PID="$!"; CHILD_PIDS+=("$!")
if [[ "${SCATTERING_MULTIHOP_CPU_LOAD:-0}" == '1' ]]; then
 for _ in 1 2 3 4; do
   sudo timeout 9s ip netns exec "$NSR" sh -c 'while :; do :; done' >/dev/null 2>&1 & LOAD_PIDS+=("$!")
 done
fi
sleep .5
if [[ "$RESEAL" == "1" ]]; then
 sudo ip netns exec "$NSA" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" send-synthetic "$PACER" 10.252.41.2 49001 5 "$WORK/a.key" 50000 >"$WORK/a.report" 2>"$WORK/a.err" & PID_A="$!"
 sudo ip netns exec "$NSB" "$NODE" "$ROOT/scripts/scattering-physical-probe.mjs" send-synthetic "$PACER" 10.252.42.2 49002 5 "$WORK/b.key" 50000 >"$WORK/b.report" 2>"$WORK/b.err" & PID_B="$!"
else
 sudo ip netns exec "$NSA" "$PACER" -target 10.252.41.2:49001 -queue-dir "$WORK/sender-a" -period-us 50000 -poll 10ms -duration 5s >"$WORK/a.report" 2>"$WORK/a.err" & PID_A="$!"
 sudo ip netns exec "$NSB" "$PACER" -target 10.252.42.2:49002 -queue-dir "$WORK/sender-b" -period-us 50000 -poll 10ms -duration 5s >"$WORK/b.report" 2>"$WORK/b.err" & PID_B="$!"
fi
CHILD_PIDS+=("$PID_A" "$PID_B")
wait "$PID_A" || { cat "$WORK/a.err" >&2;exit 1; }
wait "$PID_B" || { cat "$WORK/b.err" >&2;exit 1; }
for p in "$RELAY_PID" "$RECEIVE_PID" "$EGRESS_PID"; do
 if ! wait "$p";then
   echo "Lab process failed: $p" >&2
   for f in "$WORK/relay.err" "$WORK/receive.err" "$WORK/egress.err"; do cat "$f" >&2; done
   exit 1
 fi
done
for p in "${CAP_PIDS[@]}";do wait "$p" || true; done
"$NODE" --input-type=module - "$ROOT" "$WORK" <<'NODE'
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const [root,work]=process.argv.slice(2);
const {assessCrossHopLinkability}=await import(pathToFileURL(resolve(root,'lib/quantic/scattering-multihop-observer.mjs')).href);
const get=n=>readFileSync(resolve(work,n));
const x=assessCrossHopLinkability(get('a.pcap'),get('b.pcap'),get('out.pcap'));
const relay=JSON.parse(get('relay.json').toString().trim().split('\n').at(-1));
const sent=get('egress.report').toString();
const match=/planned=(\d+) sent=(\d+) missed=(\d+)/.exec(sent);
if(!match)throw Error('Go egress pacer counters missing');
const native={planned:Number(match[1]),sent:Number(match[2]),missed:Number(match[3])};
if(relay.ingressA<50||relay.ingressB<50||
 relay.spooled!==relay.ingressA+relay.ingressB||relay.spoolErrors!==0||
 x.ingress.A!==relay.ingressA||x.ingress.B!==relay.ingressB||
 x.egress.cells>native.sent||x.egress.repeatedCiphertext!==0)
 throw Error('multi-hop capture mismatch or missing relayed traffic');
const reseal=process.env.SCATTERING_MULTIHOP_RESEAL==='1';
const rxLines=get('receive.json').toString().trim().split('\n');
const receiver=JSON.parse(rxLines.at(-1));
if(reseal){
 if(relay.mode!=='trusted-hop-reseal-lab'||relay.ciphertextModified!==true||
    receiver.mode!=='physical-synthetic-receive'||receiver.authenticatedPayloadProven!==true||
    receiver.authenticatedSynthetic<50||receiver.replays!==0||
    x.egress.matchedUnique!==0)throw Error('trusted test-hop did not re-encrypt and authenticate');
}else{
 if(relay.mode!=='synthetic-keyless-opaque-relay'||
    x.egress.matchedPerSender.A<30||x.egress.matchedPerSender.B<30)
   throw Error('opaque relay negative control was not linkable');
 if(process.env.SCATTERING_MULTIHOP_IMPAIRMENT!=='1'&&x.ingressMatchedRate<.90)
   throw Error('healthy opaque relay forwarded fewer than 90% of inputs');
}
console.log(JSON.stringify({lab:reseal?'trusted-hop-reseal-control':'negative-control-2-senders-1-opaque-relay',
 CPUContentionRequested:process.env.SCATTERING_MULTIHOP_CPU_LOAD==='1',
 impairmentRequested:process.env.SCATTERING_MULTIHOP_IMPAIRMENT==='1',
 native,relay,receiver:{received:receiver.received,authenticatedSynthetic:receiver.authenticatedSynthetic??0,
  replays:receiver.replays??0,unauthenticated:receiver.unauthenticated??0},
 x,releaseReady:false},null,2));
NODE
