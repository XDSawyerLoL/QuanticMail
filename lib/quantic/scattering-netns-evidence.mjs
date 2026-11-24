// Research-only parser for tcpdump -tt -n on a synthetic isolated veth link.
// No PCAP bytes or IP addresses are exported. Not a proof of anonymity.
import {readFileSync} from 'node:fs';
import {traceMetrics} from './scattering-wire-metrics.mjs';

export function parseTcpdumpLines(source) {
  if (typeof source !== 'string') throw new Error('invalid tcpdump source');
  const times = [], lengths = [];
  for (const line of source.split(/\r?\n/)) {
    // Exact tcpdump IPv4 UDP summary format. Strictly refuse unexpected data.
    const match = /^\s*(\d+\.\d+)\s+IP\s+.+:\s+UDP,\s+length\s+(\d+)\s*$/.exec(line);
    if (match) {
      times.push(Number(match[1]) * 1000);
      lengths.push(Number(match[2]));
    }
  }
  if (!times.length) throw new Error('no IPv4 UDP tcpdump packets found');
  if (times.length > 100000) throw new Error('trace too large');
  return {times, lengths};
}
function parseJsonLastLine(raw) {
  for (const line of raw.split(/\r?\n/).reverse()) {
    try {const value=JSON.parse(line);if (value && typeof value==='object')return value;}
    catch {}
  }
  throw new Error('probe JSON result not found');
}
export function analyzeNamespacePair(input) {
  const conditions = {};
  for (const mode of ['cover', 'synthetic']) {
    const data = input[mode];
    if (!data || typeof data.capture !== 'string' ||
        typeof data.sender !== 'string' || typeof data.receiver !== 'string') {
      throw new Error('missing condition input');
    }
    const {times,lengths}=parseTcpdumpLines(data.capture);
    const passive=traceMetrics(times,lengths,20);
    const sender=parseJsonLastLine(data.sender);
    const receiver=parseJsonLastLine(data.receiver);
    const native=/planned=(\d+) sent=(\d+) missed=(\d+)/.exec(sender.report || '');
    if (!native) throw new Error('native sender counters missing');
    const planned=Number(native[1]), sent=Number(native[2]), missed=Number(native[3]);
    if (sender.mode !== (mode==='cover'?'physical-cover-send':'physical-synthetic-send') ||
        receiver.mode !== 'physical-cover-receive' ||
        !Number.isSafeInteger(receiver.received) ||
        !Number.isSafeInteger(receiver.malformed) ||
        receiver.received < 1 || passive.received < 1 ||
        passive.unexpectedLengths !== 0 || receiver.malformed !== 0 ||
        planned <= 0 || sent < 1 || sent > planned || missed > planned ||
        passive.received > sent || receiver.received > sent) {
      throw new Error('invalid capture or sender/receiver evidence');
    }
    conditions[mode] = {
      sender: {planned,sent,missed},
      passive, receiver: {received:receiver.received,malformed:receiver.malformed},
    };
  }
  const a=conditions.cover, b=conditions.synthetic;
  return {
    experiment: 'Scattering veth network namespace passive observer',
    evidenceLevel: 'two-network-namespaces-single-linux-host',
    independentPassiveCaptureProcess: true,
    twoPhysicalHostsTested: false,
    realWanTested: false,
    strongAdversaryTested: false,
    nativeUdpPacketBytes: 168,
    conditions,
    deltas: {
      capturedBusyMinusCover: b.passive.received - a.passive.received,
      p95GapBusyMinusCoverMs: +(b.passive.p95GapMs - a.passive.p95GapMs).toFixed(3),
      medianGapBusyMinusCoverMs: +(b.passive.medianGapMs - a.passive.medianGapMs).toFixed(3),
    },
    securityClaim: 'NONE: timing and packet-count observation only, no private keys, no real users, no anonymity guarantee',
  };
}
export function analyzeNamespacePairPaths([coverCapture,coverSend,coverReceive,busyCapture,busySend,busyReceive]) {
  return analyzeNamespacePair({
    cover: {
      capture:readFileSync(coverCapture,'utf8'),sender:readFileSync(coverSend,'utf8'),
      receiver:readFileSync(coverReceive,'utf8'),
    },
    synthetic: {
      capture:readFileSync(busyCapture,'utf8'),sender:readFileSync(busySend,'utf8'),
      receiver:readFileSync(busyReceive,'utf8'),
    },
  });
}
