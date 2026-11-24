#!/usr/bin/env node
// Research-only test: real native pacer over UDP loopback, not an Internet test.
// Does not contact external addresses or use accounts, identity keys, or messages.
import {createSocket} from 'node:dgram';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {mkdir, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {isAbsolute, join} from 'node:path';
import {performance} from 'node:perf_hooks';
import {traceMetrics, summarizePairs} from '../lib/quantic/scattering-wire-metrics.mjs';
import {sealReliable} from '../labs/quantic-native/scattering/scattering-reliable-lab.mjs';
import {writeSpool} from '../labs/quantic-native/scattering/scattering-cell.mjs';

const PERIOD_US = 20000;
const PACKET_BYTES = 168;
const PERMITTED = {duration: [2, 8], pairs: [1, 6]};
const check = (ok, msg) => { if (!ok) throw new Error(msg); };
const hash = data => createHash('sha256').update(data).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function runPacer(binary, queueDir, target, duration) {
  return await new Promise((resolve, reject) => {
    const args = ['-mode', 'send', '-target', target, '-queue-dir', queueDir,
      '-period-us', String(PERIOD_US), '-poll', '10ms', '-wait-mode', 'native',
      '-duration', duration + 's'];
    const child = spawn(binary, args, {shell: false, windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']});
    let output = '', err = '', settled = false;
    const timeout = setTimeout(() => child.kill(), duration * 1000 + 10000);
    child.stdout.on('data', data => {output = (output + data.toString()).slice(-4096);});
    child.stderr.on('data', data => {err = (err + data.toString()).slice(-4096);});
    child.once('error', error => finish(error));
    child.once('close', (code, signal) => finish(code === 0 ? null :
      new Error('native pacer failed or timed out: ' + (signal || code) + ' ' + err)));
    function finish(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error) { reject(error); return; }
      const match = /planned=(\d+) sent=(\d+) missed=(\d+)/.exec(output);
      if (!match) {reject(new Error('pacer report missing required counters')); return;}
      resolve({planned: Number(match[1]), sent: Number(match[2]),
        missed: Number(match[3])});
    }
  });
}

async function oneTrial(binary, busy, duration) {
  const home = await mkdtemp(join(tmpdir(), 'qs-wire-observer-'));
  const socket = createSocket('udp4');
  const timestamps = [], lengths = [];
  const syntheticHashes = new Set();
  let matchedSynthetic = 0;
  try {
    const queueDir = join(home, 'queue');
    await mkdir(queueDir, {mode: 0o700});
    if (busy) {
      // Packets are genuine AES-256-GCM *synthetic* lab frames.
      // The native process cannot read the key; the timing observer never uses it.
      const key = randomBytes(32);
      const cells = [];
      const count = Math.ceil(duration * 1000000 / PERIOD_US) + 40;
      for (let seq = 0; seq < count; seq++) {
        const cell = sealReliable(key, {seq, ack: 0, data: randomBytes(128)});
        check(cell.length === PACKET_BYTES, 'invalid lab frame');
        cells.push(cell);
        syntheticHashes.add(hash(cell));
      }
      key.fill(0);
      writeSpool(queueDir, cells);
    }
    socket.on('message', datagram => {
      timestamps.push(performance.now());
      lengths.push(datagram.length);
      if (busy && syntheticHashes.has(hash(datagram))) matchedSynthetic++;
    });
    await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(0, '127.0.0.1', resolve);
    });
    const pacer = await runPacer(binary, queueDir,
      '127.0.0.1:' + socket.address().port, duration);
    await delay(100);
    const rx = traceMetrics(timestamps, lengths, PERIOD_US / 1000);
    check(rx.received >= 2, 'too few UDP datagrams reached the loopback observer');
    check(rx.unexpectedLengths === 0, 'bad UDP datagram length');
    check(pacer.sent <= pacer.planned && pacer.sent + pacer.missed <= pacer.planned,
      'invalid native counters');
    check(rx.received <= pacer.sent, 'received more UDP cells than native reported');
    check(!busy || matchedSynthetic > 0, 'native pacer did not emit prepared ciphertext');
    check(busy || matchedSynthetic === 0, 'idle trial matched synthetic data');
    return {mode: busy ? 'synthetic-payload' : 'idle-cover', pacer, rx,
      // Known ciphertext is used only for the internal positive control.
      // Exclude it from observer features; do not export packet bytes.
      knownSyntheticDelivered: matchedSynthetic};
  } finally {
    socket.close();
    await rm(home, {force: true, recursive: true});
  }
}

async function main() {
  const [binary, durationRaw = '3', pairsRaw = '2'] = process.argv.slice(2);
  const duration = Number(durationRaw), pairCount = Number(pairsRaw);
  check(typeof binary === 'string' && isAbsolute(binary), 'absolute pacer path required');
  check(Number.isInteger(duration) && duration >= PERMITTED.duration[0] &&
    duration <= PERMITTED.duration[1] && Number.isInteger(pairCount) &&
    pairCount >= PERMITTED.pairs[0] && pairCount <= PERMITTED.pairs[1],
    'usage: node scripts/scattering-wire-observer-lab.mjs ABS_PACER [duration=3] [pairs=2]');
  const pairs = [];
  for (let index = 0; index < pairCount; index++) {
    // Alternate condition order to reduce systematic drift.
    const order = index % 2 ? [true, false] : [false, true];
    const result = {};
    for (const busy of order) result[busy ? 'busy' : 'idle'] = await oneTrial(binary, busy, duration);
    pairs.push(result);
  }
  console.log(JSON.stringify({
    tool: 'Scattering real native UDP loopback observer laboratory',
    evidenceLevel: 'local-loopback-only',
    twoPhysicalHostsTested: false, independentPassiveTap: false,
    packetSizeBytes: PACKET_BYTES, periodUs: PERIOD_US,
    conditions: 'idle random cover versus queued authenticated synthetic cells',
    observerFeatures: ['receive packet count', 'packet lengths', 'interarrival gaps'],
    paired: summarizePairs(pairs), pairs,
    limitations: 'UDP loopback endpoint is also the receiver; no WAN paths, independent passive tap, peer compromise or metadata unlinkability claims.',
  }, null, 2));
}

main().catch(error => {console.error('Scattering wire lab failed: ' + error.message); process.exitCode = 1;});
