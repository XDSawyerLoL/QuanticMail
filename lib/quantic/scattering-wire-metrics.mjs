// Receiver-side UDP timing statistics only. This is NOT an anonymity test.
const numeric = values => Array.isArray(values) && values.every(x => Number.isFinite(x));
function quantile(sorted, p) {
  if (!sorted.length) return null;
  return sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)];
}
export function traceMetrics(timestampsMs, packetLengths, nominalPeriodMs) {
  if (!numeric(timestampsMs) || !numeric(packetLengths) || timestampsMs.length !== packetLengths.length ||
      !Number.isFinite(nominalPeriodMs) || nominalPeriodMs <= 0 ||
      timestampsMs.some((v, i) => i && v < timestampsMs[i - 1]) ||
      packetLengths.some(n => !Number.isInteger(n) || n < 0)) {
    throw new Error('invalid wire trace');
  }
  const gaps = timestampsMs.slice(1).map((x, i) => x - timestampsMs[i]).sort((a,b)=>a-b);
  const round = x => x === null ? null : +x.toFixed(3);
  return {
    received: timestampsMs.length,
    bytes: packetLengths.reduce((a,b)=>a+b,0),
    length168: packetLengths.filter(x=>x===168).length,
    unexpectedLengths: packetLengths.filter(x=>x!==168).length,
    medianGapMs: round(quantile(gaps, .5)),
    p95GapMs: round(quantile(gaps, .95)),
    p99GapMs: round(quantile(gaps, .99)),
    maxGapMs: round(gaps.at(-1) ?? null),
    gapsOver2Periods: gaps.filter(x => x > 2 * nominalPeriodMs).length,
    // Raw gaps can be used by the count/timing observer, never payload bytes.
  };
}
export function summarizePairs(pairs) {
  if (!Array.isArray(pairs) || !pairs.length || pairs.some(x =>
      !x || !x.idle || !x.busy || !Number.isFinite(x.idle.rx.received) ||
      !Number.isFinite(x.busy.rx.received))) throw new Error('invalid paired traces');
  const avg = values => +((values.reduce((a,b)=>a+b,0))/values.length).toFixed(3);
  const differences = (key) => pairs.map(p=>p.busy.rx[key] - p.idle.rx[key]);
  return {
    pairs: pairs.length,
    avgReceiverCountDifferenceBusyMinusIdle: avg(differences('received')),
    avgMedianGapDifferenceMs: avg(differences('medianGapMs')),
    avgP95GapDifferenceMs: avg(differences('p95GapMs')),
    // Descriptive only: labels are KNOWN during measurement, no blind classifier.
    interpretation: 'Descriptive side-channel comparison only; no independence test or security guarantee.',
  };
}
