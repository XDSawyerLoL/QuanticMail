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
E2E="${SCATTERING_MULTIHOP_E2E:-0}"
MIX="${SCATTERING_MULTIHOP_MIX:-0}"
OFFSET="${SCATTERING_MULTIHOP_SOURCE_OFFSET_MS:-0}"
B_REAL="${SCATTERING_MULTIHOP_B_REAL_CELLS:-100}"
if [[ "$B_REAL" != "100" && "$B_REAL" != "20" ]];then echo 'unsupported real-cell mix' >&2;exit 2;fi
if [[ "$B_REAL" == "20" && "$E2E" != "1" ]];then echo 'skew needs E2E lab' >&2;exit 2;fi
B_PRELOAD="140"
EXPECTED_COVER="0"
if [[ "$B_REAL" == "20" ]];then B_PRELOAD="20";EXPECTED_COVER="80";fi
if [[ "$OFFSET" != "0" && "$OFFSET" != "25" ]];then
 echo 'unsupported source offset' >&2; exit 2
fi
if [[ "$MIX" == "1" && "$E2E" != "1" ]];then echo 'batch-mix requires E2E lab' >&2;exit 2;fi
if [[ "$E2E" == "1" && "$RESEAL" != "1" ]]; then
 echo 'E2E test requires independent hop resealing' >&2; exit 2
fi
if [[ "$RESEAL" == "1" ]]; then
 for name in a b out; do
  "$NODE" -e "require('node:fs').writeFileSync(process.argv[1],require('node:crypto').randomBytes(32),{mode:0o600})" "$WORK/$name.key"
 done
fi
if [[ "$E2E" == "1" ]]; then
 # The relay receives only per-hop key paths. Inner key remains endpoint-only.
 "$NODE" -e "require('node:fs').writeFileSync(process.argv[1],require('node:crypto').randomBytes(32),{mode:0o600})" "$WORK/e2e.key"
fi
# Capture binary PCAPs to stdout (opened by unprivileged shell), never as artifacts.
sudo timeout -s INT 17s ip netns exec "$NSR" tcpdump -i "$VAR" -Q in -n -s 256 -U -w - 'udp and dst port 49001' >"$WORK/a.pcap" 2>"$WORK/a.caplog" & CAP_PIDS+=("$!")
sudo timeout -s INT 17s ip netns exec "$NSR" tcpdump -i "$VBR" -Q in -n -s 256 -U -w - 'udp and dst port 49002' >"$WORK/b.pcap" 2>"$WORK/b.caplog" & CAP_PIDS+=("$!")
sudo timeout -s INT 17s ip netns exec "$NSD" tcpdump -i "$VDR" -Q in -n -s 256 -U -w - 'udp and dst port 49003' >"$WORK/out.pcap" 2>"$WORK/out.caplog" & CAP_PIDS+=("$!")
sleep .8
if [[ "$RESEAL" == "1" ]]; then
 sudo ip netns exec "$NSR" "$NODE" "$ROOT/scripts/scattering-hop-reseal-relay-lab.mjs" 10.252.41.2:49001 10.252.42.2:49002 "$WORK/queue" 12 "$WORK/a.key" "$WORK/b.key" "$WORK/out.key" "$MIX" "$EXPECTED_COVER" >"$WORK/relay.json" 2>"$WORK/relay.err" &
else
 sudo ip netns exec "$NSR" "$NODE" "$ROOT/scripts/scattering-opaque-relay-lab.mjs" 10.252.41.2:49001 10.252.42.2:49002 "$WORK/queue" 12 >"$WORK/relay.json" 2>"$WORK/relay.err" &
fi
RELAY_PID="$!"; CHILD_PIDS+=("$!")
if [[ "$E2E" == "1" ]]; then
 sudo ip netns exec "$NSD" "$NODE" "$ROOT/scripts/scattering-e2e-receiver-lab.mjs" "$PACER" 10.252.43.2 49003 13 "$WORK/out.key" "$WORK/e2e.key" >"$WORK/receive.json" 2>"$WORK/receive.err" &
elif [[ "$RESEAL" == "1" ]]; then
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
if [[ "$E2E" == "1" ]]; then
 sudo ip netns exec "$NSA" "$NODE" "$ROOT/scripts/scattering-e2e-sender-lab.mjs" "$PACER" 10.252.41.2 49001 5 "$WORK/a.key" "$WORK/e2e.key" 0 >"$WORK/a.report" 2>"$WORK/a.err" & PID_A="$!"
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
const {assessCrossHopLinkability,parseLabPcap}=await import(pathToFileURL(resolve(root,'lib/quantic/scattering-multihop-observer.mjs')).href);
const get=n=>readFileSync(resolve(work,n));
const x=assessCrossHopLinkability(get('a.pcap'),get('b.pcap'),get('out.pcap'));
const ingressA=parseLabPcap(get('a.pcap')),ingressB=parseLabPcap(get('b.pcap'));
const measuredFirstSourceOffsetMs=+(ingressB.packets[0].timestampMs-ingressA.packets[0].timestampMs).toFixed(3);
const relay=JSON.parse(get('relay.json').toString().trim().split('\n').at(-1));
const sent=get('egress.report').toString();
const match=/planned=(\d+) sent=(\d+) missed=(\d+)/.exec(sent);
if(!match)throw Error('Go egress pacer counters missing');
const native={planned:Number(match[1]),sent:Number(match[2]),missed:Number(match[3])};
if(relay.ingressA<50||
 relay.ingressB<(process.env.SCATTERING_MULTIHOP_B_REAL_CELLS==='20'?20:50)||
 relay.spooled!==relay.ingressA+relay.ingressB||relay.spoolErrors!==0||
 x.ingress.A!==100||x.ingress.B!==100||
 x.egress.cells>native.sent||x.egress.repeatedCiphertext!==0)
 throw Error('multi-hop capture mismatch or missing relayed traffic');
const reseal=process.env.SCATTERING_MULTIHOP_RESEAL==='1';
const e2e=process.env.SCATTERING_MULTIHOP_E2E==='1';
const mix=process.env.SCATTERING_MULTIHOP_MIX==='1';
const bReal=Number(process.env.SCATTERING_MULTIHOP_B_REAL_CELLS||100);
const expectedData=e2e?100+bReal:200;
const expectedCover=bReal===20?80:0;
const rxLines=get('receive.json').toString().trim().split('\n');
const receiver=JSON.parse(rxLines.at(-1));
if(e2e){
 if((relay.mixedBatches===true)!==mix)throw Error('relay batch mixing expectation mismatch');
 if(mix&&(relay.mixer?.batchSize!==40||relay.mixer?.batches!==expectedData/40||
          relay.mixer?.pending!==0||relay.mixer?.emitted!==expectedData))
    throw Error('mixed batch-count/completeness requirement failed');
 if(!reseal||relay.mode!=='trusted-hop-reseal-lab'||relay.ciphertextModified!==true||
    relay.unauthenticated!==expectedCover||
    receiver.mode!=='nested-e2e-synthetic-receive'||receiver.authenticatedE2E!==expectedData||
    receiver.authenticatedHop!==expectedData||receiver.perSender.A!==100||receiver.perSender.B!==bReal||
    receiver.invalidInner!==0||receiver.duplicates!==0||x.egress.matchedUnique!==0)
    throw Error('nested end-to-end message was not authenticated and correlated correctly');
}else if(reseal){
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
let timeOnlyObserver=null;
if(e2e){
 const {evaluateTimeOnlyLab}=await import(pathToFileURL(resolve(root,'lib/quantic/scattering-temporal-correlation-lab.mjs')).href);
 const hopKey=get('out.key'),contentKey=get('e2e.key');
 try{
  timeOnlyObserver=evaluateTimeOnlyLab({
   captureA:get('a.pcap'),captureB:get('b.pcap'),captureEgress:get('out.pcap'),
   outputHopKey:hopKey,endToEndKey:contentKey,maxLagMs:250
  });
  if(timeOnlyObserver.data.total!==expectedData||timeOnlyObserver.truth.A!==100||
     timeOnlyObserver.truth.B!==bReal||timeOnlyObserver.observedPackets!==native.sent)
    throw Error('temporal scorer observed incomplete authenticated truth');
 }finally{hopKey.fill(0);contentKey.fill(0);}
}
console.log(JSON.stringify({lab:mix?'nested-e2e-40-cell-randomized-mix':e2e?'nested-e2e-inner-under-trusted-hop':reseal?'trusted-hop-reseal-control':'negative-control-2-senders-1-opaque-relay',
 CPUContentionRequested:process.env.SCATTERING_MULTIHOP_CPU_LOAD==='1',
 sourceOffsetRequestedMs:Number(process.env.SCATTERING_MULTIHOP_SOURCE_OFFSET_MS||0),
 sourceBRealMessagesRequested:e2e?bReal:null,
 measuredFirstSourceOffsetMs,
 impairmentRequested:process.env.SCATTERING_MULTIHOP_IMPAIRMENT==='1',
 native,relay,receiver:{received:receiver.received,authenticatedSynthetic:receiver.authenticatedSynthetic??0,
  authenticatedHop:receiver.authenticatedHop??0,authenticatedE2E:receiver.authenticatedE2E??0,
  perSender:receiver.perSender??null,replays:receiver.replays??0,unauthenticated:receiver.unauthenticated??0},
 e2eKeyProvisionedToRelay:false,sharedHostFileSystemAccess:true,
 timeOnlyObserver,x,releaseReady:false},null,2));
NODE
