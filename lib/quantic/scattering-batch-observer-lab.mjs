// Reproducible *idealized* batch-source attribution model. No network,
// encryption, relay code, or actual mixnet. PRNG must NEVER be used for crypto.
// Attacker sees all ingress senders and per-window message counts, then guesses
// the most frequent sender for each indistinguishable shuffled output.
function rng(seed) {
  let x = seed >>> 0;
  if (x === 0) x = 0x9e3779b9;
  return () => {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    return (x >>> 0) / 4294967296;
  };
}
function params(options = {}) {
  const p = {
    users: 12, ticks: 6400, windowTicks: 8, probability: 0.025,
    dominantMultiplier: 1, seed: 20261123, ...options,
  };
  if (![p.users, p.ticks, p.windowTicks, p.dominantMultiplier, p.seed]
      .every(Number.isSafeInteger) || p.users < 2 || p.users > 100 ||
      p.ticks < 100 || p.ticks > 200000 || p.windowTicks < 1 ||
      p.windowTicks > p.ticks || p.dominantMultiplier < 1 ||
      p.dominantMultiplier > 100 || p.seed < 0 || p.seed > 0xffffffff ||
      !Number.isFinite(p.probability) || p.probability < 0 ||
      p.probability > 1 || p.probability * p.dominantMultiplier > 1) {
    throw new Error('invalid observer parameters');
  }
  return p;
}
export function studyObserver(options = {}) {
  const p = params(options), random = rng(p.seed);
  let arrivals = 0, windowsWithData = 0, mixedWindows = 0;
  let largestGuess = 0, singleSenderMessages = 0, activeSendersTotal = 0;
  let current = new Uint32Array(p.users), inCurrent = 0;
  function finishWindow() {
    const total = current.reduce((a, b) => a + b, 0);
    if (total) {
      windowsWithData++;
      const max = Math.max(...current);
      const distinct = current.reduce((a, x) => a + (x ? 1 : 0), 0);
      largestGuess += max;
      activeSendersTotal += distinct;
      if (distinct >= 2) mixedWindows++;
      if (distinct === 1) singleSenderMessages += total;
    }
    current = new Uint32Array(p.users);
    inCurrent = 0;
  }
  for (let tick = 0; tick < p.ticks; tick++) {
    for (let user = 0; user < p.users; user++) {
      const chance = p.probability * (user === 0 ? p.dominantMultiplier : 1);
      if (random() < chance) {current[user]++; arrivals++;}
    }
    inCurrent++;
    if (inCurrent === p.windowTicks) finishWindow();
  }
  if (inCurrent) finishWindow();
  return {
    users: p.users, ticks: p.ticks, windowTicks: p.windowTicks,
    probability: p.probability, dominantMultiplier: p.dominantMultiplier,
    arrivals, windowsWithData, mixedWindows, singleSenderMessages,
    meanActiveSendersPerNonemptyWindow: windowsWithData ? activeSendersTotal / windowsWithData : null,
    // Optimum source attribution within each shuffled batch, GIVEN that the
    // adversary knows exact ingress counts but not the secret permutation.
    // This is not a network-level probability and ignores output metadata.
    idealizedSourceGuessRate: arrivals ? largestGuess / arrivals : null,
    // Explicit negative controls: an uncompromised, perfectly unlinkable mix
    // is assumed above; a relay exposing a sender-tag mapping defeats that assumption.
    mappedTagSourceGuessRate: arrivals ? 1 : null,
  };
}
function meanAndInterval(values) {
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.length < 2 ? 0 :
    values.reduce((a, b) => a + (b - mean) ** 2, 0) / (values.length - 1);
  const halfWidth = 1.96 * Math.sqrt(variance / values.length);
  return {mean: +mean.toFixed(6), lower95: +Math.max(0, mean - halfWidth).toFixed(6),
    upper95: +Math.min(1, mean + halfWidth).toFixed(6)};
}
export function compareObserverScenarios({trials = 24, seed = 20261123, ticks = 6400,
  users = 12} = {}) {
  if (![trials, seed, ticks, users].every(Number.isSafeInteger) ||
      trials < 2 || trials > 500 || seed < 0 || seed > 0xffffffff ||
      users < 2 || users > 100 || ticks < 100 || ticks > 200000) {
    throw new Error('invalid comparison parameters');
  }
  const scenarios = [
    {name: 'sparse', probability: 0.005, dominantMultiplier: 1},
    {name: 'busy-balanced', probability: 0.06, dominantMultiplier: 1},
    {name: 'busy-dominant-sender', probability: 0.03, dominantMultiplier: 8},
  ];
  const results = [];
  for (const scenario of scenarios) {
    for (const windowTicks of [1, 8, 32]) {
      const samples = Array.from({length: trials}, (_, i) => studyObserver({
        ...scenario, users, ticks, windowTicks, seed: (seed + i * 1009) >>> 0,
      }));
      const values = samples.map(x => x.idealizedSourceGuessRate).filter(x => x !== null);
      results.push({scenario: scenario.name, windowTicks, trials,
        avgArrivals: Math.round(samples.reduce((a, x) => a + x.arrivals, 0) / trials),
        ...meanAndInterval(values),
        avgSingleSenderMessageFraction: +(
          samples.reduce((a, x) => a + x.singleSenderMessages, 0) /
          Math.max(1, samples.reduce((a, x) => a + x.arrivals, 0))
        ).toFixed(6),
        mappedTagGuessRate: 1,
      });
    }
  }
  return {description: 'Synthetic idealized uniform batch shuffling; NOT network anonymity',
    assumptions: [
      'Observer knows the exact sender counts per batch and has no ciphertext or routing identifier for each output.',
      'Every message in the same batch is uniformly shuffled, with no residual timing or network metadata.',
      'A stable visible tag enables within-epoch clustering, but not automatic identification of the sender.',
      'A compromised gateway or external known tag-to-sender mapping permits direct sender attribution.',
      'Confidence intervals approximate uncertainty across synthetic random seeds, NOT real-world protection.',
    ], results};
}
