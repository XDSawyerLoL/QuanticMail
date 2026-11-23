// Synthetic, deterministic scheduling laboratory: no sockets, crypto, identities,
// side channels or claims of anonymity. NEVER use this PRNG for cryptographic scheduling.
const MODES = ['fixed-cover', 'batch-no-cover', 'hybrid-cover-batch'];
export const CELL_BYTES = 168;
function randomGenerator(seed) {
  let state = seed >>> 0;
  if (!state) state = 0x9e3779b9;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
}
function checkedOptions(options = {}) {
  const p = {ticks: 12000, tickMs: 50, cellsPerTick: 2, batchTicks: 8,
    arrivalProbability: 0.15, burstCells: 4, queueLimit: 512, seed: 20261123, ...options};
  const ints = ['ticks', 'tickMs', 'cellsPerTick', 'batchTicks', 'burstCells', 'queueLimit', 'seed'];
  if (!ints.every(name => Number.isSafeInteger(p[name])) ||
      p.ticks < 16 || p.ticks > 100000 || p.tickMs < 1 || p.tickMs > 1000 ||
      p.cellsPerTick < 1 || p.cellsPerTick > 100 || p.batchTicks < 2 || p.batchTicks > 100 ||
      p.burstCells < 1 || p.burstCells > 100 || p.queueLimit < 1 || p.queueLimit > 100000 ||
      p.seed < 0 || p.seed > 0xffffffff ||
      !Number.isFinite(p.arrivalProbability) ||
      p.arrivalProbability < 0 || p.arrivalProbability > 1) {
    throw new Error('invalid simulation parameters');
  }
  return Object.freeze(p);
}
export function generateArrivals(options = {}) {
  const p = checkedOptions(options);
  const random = randomGenerator(p.seed);
  return Array.from({length: p.ticks}, () =>
    random() < p.arrivalProbability ? p.burstCells : 0);
}
function percentile(sorted, probability) {
  return sorted.length ? sorted[Math.max(0, Math.ceil(sorted.length * probability) - 1)] : null;
}
// All modes receive the same synthetic arrivals and average service budget.
// Batch-no-cover deliberately has a higher instantaneous peak at batch boundaries.
export function simulateSchedule(mode, options = {}, arrivalsInput = null) {
  if (!MODES.includes(mode)) throw new Error('invalid schedule mode');
  const p = checkedOptions(options);
  const arrivals = arrivalsInput ?? generateArrivals(p);
  if (!Array.isArray(arrivals) || arrivals.length !== p.ticks ||
      arrivals.some(n => !Number.isSafeInteger(n) || n < 0 || n > 10000))
    throw new Error('invalid arrivals');
  const pending = [], waitTicks = [], wireCounts = [];
  let pendingHead = 0, ready = [], readyHead = 0;
  let admitted = 0, dropped = 0, sent = 0, cellsOnWire = 0, maxQueue = 0;
  const pendingLength = () => pending.length - pendingHead;
  const readyLength = () => ready.length - readyHead;
  const queueLength = () => pendingLength() + readyLength();
  function dequeuePending() {
    const item = pending[pendingHead++];
    if (pendingHead >= 1024) {pending.splice(0, pendingHead); pendingHead = 0;}
    return item;
  }
  function dequeueReady() {
    const item = ready[readyHead++];
    if (readyHead >= 1024) {ready.splice(0, readyHead); readyHead = 0;}
    return item;
  }
  const shuffle = randomGenerator(p.seed ^ 0xa5a50f0f);
  // Non-cryptographic synthetic shuffle, NOT actual mixnet anonymity.
  function releaseBatch() {
    const take = Math.min(p.batchTicks * p.cellsPerTick, pendingLength());
    const chunk = Array.from({length: take}, dequeuePending);
    for (let i = chunk.length - 1; i > 0; i--) {
      const j = Math.floor(shuffle() * (i + 1));
      [chunk[i], chunk[j]] = [chunk[j], chunk[i]];
    }
    ready.push(...chunk);
  }
  for (let tick = 0; tick < p.ticks; tick++) {
    for (let i = 0; i < arrivals[tick]; i++) {
      if (queueLength() >= p.queueLimit) dropped++;
      else {pending.push(tick); admitted++;}
    }
    maxQueue = Math.max(maxQueue, queueLength());
    const boundary = (tick + 1) % p.batchTicks === 0;
    if (mode !== 'fixed-cover' && boundary) releaseBatch();
    const capacity = mode === 'batch-no-cover' && !boundary ? 0 :
      mode === 'batch-no-cover' ? p.cellsPerTick * p.batchTicks : p.cellsPerTick;
    let real = 0;
    for (let i = 0; i < capacity; i++) {
      if (mode === 'fixed-cover' ? !pendingLength() : !readyLength()) break;
      const originalTick = mode === 'fixed-cover' ? dequeuePending() : dequeueReady();
      waitTicks.push(tick - originalTick);
      real++;
    }
    sent += real;
    const outgoing = mode === 'batch-no-cover' ? real : p.cellsPerTick;
    wireCounts.push(outgoing);
    cellsOnWire += outgoing;
  }
  waitTicks.sort((a, b) => a - b);
  const unsent = queueLength();
  if (admitted !== sent + unsent || admitted + dropped !== arrivals.reduce((a,b)=>a+b,0))
    throw new Error('message conservation violated');
  const seconds = p.ticks * p.tickMs / 1000;
  const delay = x => {
    const v = percentile(waitTicks, x);
    return v === null ? null : v * p.tickMs;
  };
  return {
    mode, ticks: p.ticks, durationSec: seconds,
    arrivals: admitted + dropped, admitted, sent, dropped, unsent, maxQueue,
    cellsOnWire, coverCells: cellsOnWire - sent, packetBytes: CELL_BYTES,
    gigabytesPerDayOneWay: +(cellsOnWire / seconds * CELL_BYTES * 86400 / 1e9).toFixed(6),
    utilization: cellsOnWire ? +(sent / cellsOnWire).toFixed(6) : 0,
    delayP50ms: delay(.5), delayP95ms: delay(.95), delayP99ms: delay(.99),
    activeTicks: wireCounts.filter(n => n > 0).length,
    maxCellsInTick: wireCounts.reduce((m,n)=>Math.max(m,n),0),
    wireCounts,
  };
}
export function compareSchedules(options = {}) {
  const p = checkedOptions(options);
  const arrivals = generateArrivals(p);
  const results = MODES.map(mode => simulateSchedule(mode, p, arrivals));
  // Weak count-only observer comparing a real-traffic trace with an idle trace.
  const idle = Array(p.ticks).fill(0);
  const observer = MODES.map(mode => {
    const activeTrace = simulateSchedule(mode, p, arrivals).wireCounts;
    const idleTrace = simulateSchedule(mode, p, idle).wireCounts;
    return {mode, wireCountTracesIdentical: activeTrace.every((n,i) => n === idleTrace[i])};
  });
  return {
    parameters: p, results: results.map(({wireCounts, ...rest}) => rest),
    observer, observerLimit:
      'Only per-tick outgoing packet counts; no network, ingress timing, metadata, endpoints, loss or active attacker.',
  };
}
