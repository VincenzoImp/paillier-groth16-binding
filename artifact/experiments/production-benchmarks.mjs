import fs from "fs";
import os from "os";
import path from "path";
import { AbiCoder, keccak256, toUtf8Bytes } from "ethers";
import {
  createDecryptionShare,
  createDecryptionShareWithProof,
  encryptValue,
  generateThresholdKeys,
  serializeCiphertext,
  serializeKeyShare,
  serializePublicKey,
} from "../crypto/dist/paillier/index.js";
import {
  buildMerkleTree,
  computeLeaf,
  getMerkleProof,
} from "../crypto/dist/zkp/merkle.js";
import { generateMembershipProof } from "../crypto/dist/zkp/proof.js";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const resultsDir = path.resolve(import.meta.dirname, "results");
const fixturePath = path.join(resultsDir, "production-fixture-3072.json");
const outputPath = path.join(resultsDir, "production-benchmarks.json");

const CIRCUIT_WASM = path.resolve(
  repoRoot,
  "artifact/circuits/build/CrossGroupBallot_js/CrossGroupBallot.wasm",
);
const CIRCUIT_ZKEY = path.resolve(repoRoot, "artifact/circuits/build/circuit_final.zkey");

const CANONICAL_CIPHERTEXT_BYTES = 768;
const REPETITIONS = 30;
const REPLAY_BALLOT_COUNTS = [10, 50, 100, 500];
const SNARK_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const NULLIFIER_DOMAIN_TAG = keccak256(toUtf8Bytes("cgbl/nullifier-domain/v1"));
const BENCHMARK_CHAIN_ID = 31337n;
const BENCHMARK_CONTRACT_ADDRESS = "0x000000000000000000000000000000000000beef";
const ABI_CODER = AbiCoder.defaultAbiCoder();

function serializeCanonical(bigintValue) {
  const rawHex = serializeCiphertext(bigintValue);
  if (rawHex.length > CANONICAL_CIPHERTEXT_BYTES * 2) {
    throw new Error(
      `Ciphertext too large for canonical serialization: ${Math.ceil(rawHex.length / 2)} bytes`,
    );
  }
  return `0x${rawHex.padStart(CANONICAL_CIPHERTEXT_BYTES * 2, "0")}`;
}

function toHexBytes(hex) {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Array.from({ length: raw.length / 2 }, (_, i) => raw.slice(i * 2, i * 2 + 2));
}

function nonZeroByteDensity(hex) {
  const bytes = toHexBytes(hex);
  const nonZero = bytes.filter((b) => b !== "00").length;
  return {
    nonZeroBytes: nonZero,
    totalBytes: bytes.length,
    ratio: nonZero / bytes.length,
  };
}

function sorted(values) {
  return [...values].sort((a, b) => a - b);
}

function quantile(values, q) {
  if (values.length === 0) return 0;
  const xs = sorted(values);
  const pos = (xs.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (xs[base + 1] === undefined) return xs[base];
  return xs[base] + rest * (xs[base + 1] - xs[base]);
}

function summarize(values) {
  return {
    repetitions: values.length,
    medianMs: Number(quantile(values, 0.5).toFixed(3)),
    iqrMs: Number((quantile(values, 0.75) - quantile(values, 0.25)).toFixed(3)),
    minMs: Number(Math.min(...values).toFixed(3)),
    maxMs: Number(Math.max(...values).toFixed(3)),
  };
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function computeBenchmarkNullifierDomain(electionIndex) {
  // Mirror the production contract's domain derivation while keeping the
  // benchmark self-contained and deterministic.
  const encoded = ABI_CODER.encode(
    ["bytes32", "uint256", "address", "uint256"],
    [NULLIFIER_DOMAIN_TAG, BENCHMARK_CHAIN_ID, BENCHMARK_CONTRACT_ADDRESS, electionIndex],
  );
  return BigInt(keccak256(encoded)) % SNARK_SCALAR_FIELD;
}

function parseFixtureBigints(fixture) {
  const publicKey = {
    n: BigInt(`0x${fixture.publicKey.n}`),
    g: BigInt(`0x${fixture.publicKey.g}`),
  };
  publicKey.nSquared = publicKey.n * publicKey.n;

  const keyShare = {
    index: fixture.keyShare.index,
    si: BigInt(`0x${fixture.keyShare.si}`),
    n: BigInt(`0x${fixture.keyShare.n}`),
    nSquared: BigInt(`0x${fixture.keyShare.nSquared}`),
  };

  return {
    publicKey,
    keyShare,
    v: BigInt(`0x${fixture.dleq.v}`),
    vi: BigInt(`0x${fixture.dleq.vi}`),
    ciphertext: BigInt(fixture.voters[0].ciphertextHex),
  };
}

async function loadOrGenerateFixture() {
  ensureDir(resultsDir);
  if (fs.existsSync(fixturePath)) {
    return JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  }

  const keygenStart = performance.now();
  const keySet = generateThresholdKeys(3, 2, 3072);
  const keygenMs = performance.now() - keygenStart;

  const ciphertext1 = encryptValue(keySet.publicKey, 1n);
  const ciphertext2 = encryptValue(keySet.publicKey, 0n);
  const aggregate = (ciphertext1 * ciphertext2) % keySet.publicKey.nSquared;
  const share1 = createDecryptionShare(keySet.keyShares[0], aggregate, 3);
  const share2 = createDecryptionShare(keySet.keyShares[1], aggregate, 3);

  const fixture = {
    generatedAt: new Date().toISOString(),
    keyBits: keySet.publicKey.n.toString(2).length,
    keygenMs: Number(keygenMs.toFixed(3)),
    parameters: { totalShares: 3, threshold: 2 },
    publicKey: serializePublicKey(keySet.publicKey),
    keyShare: serializeKeyShare(keySet.keyShares[0]),
    dleq: {
      v: keySet.v.toString(16),
      vi: keySet.verificationKeys[0].vi.toString(16),
    },
    voters: [
      {
        secretHex: "2b67",
        addressHex: "56ce",
        plaintext: "1",
        ciphertextHex: serializeCanonical(ciphertext1),
      },
      {
        secretHex: "8235",
        addressHex: "ad9c",
        plaintext: "0",
        ciphertextHex: serializeCanonical(ciphertext2),
      },
    ],
    aggregateHex: serializeCanonical(aggregate),
    shares: [
      {
        index: share1.index,
        shareHex: `0x${share1.ci.toString(16).padStart(CANONICAL_CIPHERTEXT_BYTES * 2, "0")}`,
      },
      {
        index: share2.index,
        shareHex: `0x${share2.ci.toString(16).padStart(CANONICAL_CIPHERTEXT_BYTES * 2, "0")}`,
      },
    ],
  };

  fs.writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
  return fixture;
}

async function benchmarkProofGeneration(fixture) {
  const leaf = await computeLeaf(
    BigInt(`0x${fixture.voters[0].addressHex}`),
    BigInt(`0x${fixture.voters[0].secretHex}`),
  );
  const tree = await buildMerkleTree([leaf]);
  const merkleProof = getMerkleProof(tree, 0);
  const nullifierDomain = computeBenchmarkNullifierDomain(1n);
  const input = {
    secret: BigInt(`0x${fixture.voters[0].secretHex}`),
    address: BigInt(`0x${fixture.voters[0].addressHex}`),
    nullifierDomain,
    ciphertextHex: fixture.voters[0].ciphertextHex,
  };

  const timings = [];
  await generateMembershipProof(input, merkleProof, { wasmPath: CIRCUIT_WASM, zkeyPath: CIRCUIT_ZKEY });
  for (let i = 0; i < REPETITIONS; i++) {
    const start = performance.now();
    await generateMembershipProof(input, merkleProof, { wasmPath: CIRCUIT_WASM, zkeyPath: CIRCUIT_ZKEY });
    timings.push(performance.now() - start);
  }
  return { rawMs: timings.map((v) => Number(v.toFixed(3))), ...summarize(timings) };
}

async function main() {
  const fixture = await loadOrGenerateFixture();
  const parsed = parseFixtureBigints(fixture);

  const encryptionTimings = [];
  encryptValue(parsed.publicKey, 1n);
  for (let i = 0; i < REPETITIONS; i++) {
    const start = performance.now();
    encryptValue(parsed.publicKey, 1n);
    encryptionTimings.push(performance.now() - start);
  }

  const shareTimings = [];
  createDecryptionShareWithProof(
    parsed.keyShare,
    parsed.ciphertext,
    parsed.publicKey,
    3,
    parsed.v,
    parsed.vi,
  );
  for (let i = 0; i < REPETITIONS; i++) {
    const start = performance.now();
    createDecryptionShareWithProof(
      parsed.keyShare,
      parsed.ciphertext,
      parsed.publicKey,
      3,
      parsed.v,
      parsed.vi,
    );
    shareTimings.push(performance.now() - start);
  }

  const replayCiphertexts = Array.from({ length: Math.max(...REPLAY_BALLOT_COUNTS) }, (_, i) =>
    encryptValue(parsed.publicKey, BigInt(i % 2)),
  );
  const replay = [];
  for (const n of REPLAY_BALLOT_COUNTS) {
    const samples = [];
    for (let rep = 0; rep < REPETITIONS; rep++) {
      const start = performance.now();
      let aggregate = 1n;
      for (let i = 0; i < n; i++) {
        aggregate = (aggregate * replayCiphertexts[i]) % parsed.publicKey.nSquared;
      }
      if (aggregate === 0n) throw new Error("Unexpected zero aggregate");
      samples.push(performance.now() - start);
    }
    replay.push({
      ballots: n,
      rawMs: samples.map((v) => Number(v.toFixed(3))),
      perBallotUsMedian: Number(((quantile(samples, 0.5) / n) * 1000).toFixed(3)),
      ...summarize(samples),
    });
  }

  const proofGeneration = await benchmarkProofGeneration(fixture);

  const result = {
    benchmark: "production-parameter-benchmarks",
    generatedAt: new Date().toISOString(),
    machine: {
      platform: process.platform,
      arch: process.arch,
      cpuModel: os.cpus()[0]?.model ?? "unknown",
      cpuCount: os.cpus().length,
      node: process.version,
    },
    methodology: {
      keygen: "measured separately as a single production-parameter run",
      operationalLatency: `${REPETITIONS} repetitions after one warm-up run`,
      replayBallotCounts: REPLAY_BALLOT_COUNTS,
      proofInput: "real 3072-bit Paillier ciphertext serialized to canonical 768-byte width",
    },
    fixture: {
      path: path.relative(repoRoot, fixturePath),
      keyBits: fixture.keyBits,
      keygenMs: fixture.keygenMs,
      voter1Density: nonZeroByteDensity(fixture.voters[0].ciphertextHex),
      aggregateDensity: nonZeroByteDensity(fixture.aggregateHex),
    },
    encryption: {
      rawMs: encryptionTimings.map((v) => Number(v.toFixed(3))),
      ...summarize(encryptionTimings),
    },
    decryptionShareWithProof: {
      rawMs: shareTimings.map((v) => Number(v.toFixed(3))),
      ...summarize(shareTimings),
    },
    proofGeneration,
    aggregateReplay: replay,
  };

  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
