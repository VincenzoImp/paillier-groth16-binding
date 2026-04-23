/**
 * Aggregate Replay Scaling Experiment
 *
 * Measures the cost of transcript-based aggregate reconstruction
 * as a function of ballot count n.
 *
 * This experiment demonstrates that the auditor's replay cost is
 * linear in n and dominated by Paillier modular multiplication.
 */

import path from "path";

const cryptoPath = path.resolve(import.meta.dirname, "../crypto/dist/paillier/index.js");

async function main() {
  const crypto = await import(cryptoPath);
  const { generateThresholdKeys, encryptValue, homomorphicAdd } = crypto;

  const keySet = generateThresholdKeys(3, 2, 512);
  const { publicKey } = keySet;

  const ballotCounts = [2, 5, 10, 20, 50, 100];
  const results: { n: number; encryptMs: number; replayMs: number; perBallotReplayUs: number }[] = [];

  for (const n of ballotCounts) {
    // Encrypt n ballots
    const t0 = performance.now();
    const ciphertexts: bigint[] = [];
    for (let i = 0; i < n; i++) {
      ciphertexts.push(encryptValue(publicKey, BigInt(i % 2)));
    }
    const encryptMs = performance.now() - t0;

    // Replay: reconstruct aggregate from ciphertext list
    const t1 = performance.now();
    let aggregate = 1n;
    for (const ct of ciphertexts) {
      aggregate = (aggregate * ct) % publicKey.nSquared;
    }
    const replayMs = performance.now() - t1;

    const perBallotReplayUs = (replayMs / n) * 1000;

    results.push({ n, encryptMs: Math.round(encryptMs), replayMs: +replayMs.toFixed(3), perBallotReplayUs: +perBallotReplayUs.toFixed(1) });
  }

  console.log(JSON.stringify({
    experiment: "aggregate-replay-scaling",
    paillierModulusBits: publicKey.n.toString(2).length,
    note: "512-bit modulus for speed; production (3072-bit) would be ~36x slower per multiplication",
    results,
  }, null, 2));
}

main().catch(e => { console.error(e); process.exitCode = 1; });
