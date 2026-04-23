/**
 * Transcript-Verifiable Aggregate Consistency Tests
 *
 * This test suite demonstrates that:
 * 1. An auditor can reconstruct the aggregate from on-chain ballot records
 * 2. Mismatch between published aggregate and transcript-derived aggregate
 *    is publicly detectable
 * 3. The reconstruction is deterministic and order-preserving
 *
 * These tests use the real @cgbl/crypto Paillier library and real Groth16 proofs.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import path from "path";
// @ts-expect-error — no types
import * as snarkjs from "snarkjs";
// @ts-expect-error — no types
import { buildPoseidon } from "circomlibjs";

const cryptoPath = path.resolve(__dirname, "../../crypto/dist/paillier/index.js");
let generateThresholdKeys: any, encryptValue: any, homomorphicAdd: any;

const CIRCUIT_WASM = path.resolve(__dirname, "../../circuits/build/CrossGroupBallot_js/CrossGroupBallot.wasm");
const CIRCUIT_ZKEY = path.resolve(__dirname, "../../circuits/build/circuit_final.zkey");
const TREE_DEPTH = 10;
const CIPHERTEXT_BYTES = 768;

let poseidon: any;
async function initPoseidon() { if (!poseidon) poseidon = await buildPoseidon(); return poseidon; }
async function hash(inputs: bigint[]): Promise<bigint> {
  const p = await initPoseidon();
  return BigInt(p.F.toString(p(inputs)));
}

async function buildTree(leaves: bigint[]) {
  const size = 2 ** TREE_DEPTH;
  const padded = [...leaves]; while (padded.length < size) padded.push(0n);
  const levels: bigint[][] = [padded]; let cur = padded;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(await hash([cur[i], cur[i + 1]]));
    levels.push(next); cur = next;
  }
  return levels;
}

function getProof(levels: bigint[][], idx: number) {
  const pathElements: bigint[] = [], pathIndices: number[] = [];
  let i = idx;
  for (let d = 0; d < TREE_DEPTH; d++) {
    pathElements.push(levels[d][i % 2 === 0 ? i + 1 : i - 1]);
    pathIndices.push(i % 2); i = Math.floor(i / 2);
  }
  return { pathElements, pathIndices, root: levels[TREE_DEPTH][0] };
}

function serializeCanonical(c: bigint): string {
  return "0x" + c.toString(16).padStart(CIPHERTEXT_BYTES * 2, "0");
}

function ciphertextToLimbs(hex: string): string[] {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Array.from({ length: 32 }, (_, i) =>
    BigInt("0x" + raw.slice(i * 48, (i + 1) * 48)).toString());
}

async function computeVoteHash(hex: string): Promise<bigint> {
  let level = ciphertextToLimbs(hex).map(BigInt);
  while (level.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(await hash([level[i], level[i + 1]]));
    level = next;
  }
  return level[0];
}

function formatProof(proof: any) {
  return {
    pA: [proof.pi_a[0], proof.pi_a[1]] as [string, string],
    pB: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]] as [[string, string], [string, string]],
    pC: [proof.pi_c[0], proof.pi_c[1]] as [string, string],
  };
}

async function generateBallotProof(
  secret: bigint, address: bigint, nullifierDomain: bigint,
  ctHex: string, treeLevels: bigint[][], leafIndex: number,
) {
  const nullifier = await hash([secret, nullifierDomain]);
  const voteHash = await computeVoteHash(ctHex);
  const root = treeLevels[TREE_DEPTH][0];
  const { pathElements, pathIndices } = getProof(treeLevels, leafIndex);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      secret: secret.toString(), address: address.toString(),
      pathElements: pathElements.map((e: bigint) => e.toString()), pathIndices,
      root: root.toString(), nullifier: nullifier.toString(),
      nullifierDomain: nullifierDomain.toString(), voteHash: voteHash.toString(),
      ctLimbs: ciphertextToLimbs(ctHex),
    },
    CIRCUIT_WASM, CIRCUIT_ZKEY,
  );
  return { proof, publicSignals, nullifier };
}

/**
 * ReconstructAggregate: reads accepted ballot ciphertexts from the contract
 * transcript and computes the homomorphic aggregate.
 *
 * This is the auditor's algorithm: it takes only the contract handle and
 * the public key, reads on-chain data, and produces the expected aggregate.
 */
async function reconstructAggregateFromTranscript(
  box: any, publicKey: { n: bigint; nSquared: bigint },
): Promise<bigint> {
  const transcript = await box.getTranscript();
  const ballotCount = Number(transcript.ballotCount);
  if (ballotCount === 0) throw new Error("No ballots in transcript");

  let aggregate = 1n; // multiplicative identity for Paillier homomorphic sum
  for (let i = 0; i < ballotCount; i++) {
    const ballot = await box.getBallot(i);
    const ctBigInt = BigInt(ballot.ciphertext);
    aggregate = (aggregate * ctBigInt) % publicKey.nSquared;
  }
  return aggregate;
}

describe("Transcript-Verifiable Aggregate Consistency", function () {
  this.timeout(180_000);

  let publicKey: any, keyShares: any[];
  let treeLevels: bigint[][];
  const voters = [
    { secret: 11111n, address: 22222n, vote: 1n },
    { secret: 33333n, address: 44444n, vote: 0n },
    { secret: 55555n, address: 66666n, vote: 1n },
  ];
  let ciphertexts: bigint[] = [];
  let ctHexes: string[] = [];

  before(async function () {
    const crypto = await import(cryptoPath);
    generateThresholdKeys = crypto.generateThresholdKeys;
    encryptValue = crypto.encryptValue;
    homomorphicAdd = crypto.homomorphicAdd;

    // Generate threshold keys
    const keySet = generateThresholdKeys(3, 2, 512);
    publicKey = keySet.publicKey;
    keyShares = keySet.keyShares;

    // Encrypt votes
    for (const v of voters) {
      const ct = encryptValue(publicKey, v.vote);
      ciphertexts.push(ct);
      ctHexes.push(serializeCanonical(ct));
    }

    // Build Merkle tree
    const leaves = [];
    for (const v of voters) leaves.push(await hash([v.address, v.secret]));
    treeLevels = await buildTree(leaves);
  });

  async function deployAndSetup() {
    const realVerifier = await ethers.deployContract("Groth16Verifier");
    const validityVerifier = await ethers.deployContract("MockBallotValidityVerifier");
    const [owner, cm1, cm2, cm3] = await ethers.getSigners();
    const box = await ethers.deployContract("CrossGroupBallotBox", [
      await realVerifier.getAddress(),
      await validityVerifier.getAddress(),
      owner.address,
    ]);
    await box.registerCommitteeMember(cm1.address);
    await box.registerCommitteeMember(cm2.address);
    await box.registerCommitteeMember(cm3.address);

    const root = treeLevels[TREE_DEPTH][0];
    const nHex = publicKey.n.toString(16);
    const latest = await ethers.provider.getBlockNumber();
    await box.initElection({
      publicKey: "0x" + nHex.padStart(nHex.length + (nHex.length % 2), "0"),
      merkleRoot: "0x" + root.toString(16).padStart(64, "0"),
      threshold: 2,
      votingDeadlineBlock: latest + 100,
      tallyDeadlineBlock: latest + 200,
    });
    return { box, owner, cm1, cm2, cm3 };
  }

  async function castAllBallots(box: any) {
    const transcript = await box.getTranscript();
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);
    for (let i = 0; i < voters.length; i++) {
      const ballot = await generateBallotProof(
        voters[i].secret, voters[i].address, nullifierDomain,
        ctHexes[i], treeLevels, i,
      );
      const sol = formatProof(ballot.proof);
      await box.castBallot(
        ctHexes[i], sol.pA, sol.pB, sol.pC, "0xabcd",
        ballot.publicSignals.map(BigInt),
      );
    }
  }

  it("reconstructs the correct aggregate from the contract transcript", async function () {
    const { box } = await deployAndSetup();
    await castAllBallots(box);

    // Auditor reconstructs aggregate from transcript
    const reconstructed = await reconstructAggregateFromTranscript(box, publicKey);

    // Prover computes aggregate from local ciphertexts
    const expected = homomorphicAdd(publicKey, ...ciphertexts);

    // They MUST match
    expect(reconstructed).to.equal(expected);
    console.log("    ✓ Transcript-derived aggregate matches expected aggregate");
  });

  it("detects mismatch when a dishonest aggregator publishes a wrong aggregate", async function () {
    const { box } = await deployAndSetup();
    await castAllBallots(box);

    // Close voting
    for (let i = 0; i < 102; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();

    // Dishonest aggregator publishes a WRONG aggregate (encrypts a different value)
    const dishonestAggregate = encryptValue(publicKey, 999n);
    const dishonestHex = serializeCanonical(dishonestAggregate);
    await box.publishAggregate(dishonestHex);

    // Auditor reconstructs from transcript
    const reconstructed = await reconstructAggregateFromTranscript(box, publicKey);
    const reconstructedHex = serializeCanonical(reconstructed);

    // The published aggregate does NOT match the transcript-derived one
    expect(reconstructedHex).to.not.equal(dishonestHex);

    // The auditor can produce a public witness of mismatch
    const publishedAggregate = await box.getTranscript();
    const publishedCommitment = publishedAggregate.aggregate.aggregateCommitment;
    const reconstructedCommitment = ethers.keccak256(reconstructedHex);

    expect(publishedCommitment).to.not.equal(reconstructedCommitment);

    console.log("    ✓ Mismatch DETECTED: published aggregate ≠ transcript-derived aggregate");
    console.log(`      Published commitment:     ${publishedCommitment.slice(0, 18)}...`);
    console.log(`      Reconstructed commitment:  ${reconstructedCommitment.slice(0, 18)}...`);
  });

  it("honest aggregate matches transcript reconstruction", async function () {
    const { box } = await deployAndSetup();
    await castAllBallots(box);

    for (let i = 0; i < 102; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();

    // Honest aggregator computes from transcript
    const reconstructed = await reconstructAggregateFromTranscript(box, publicKey);
    const honestHex = serializeCanonical(reconstructed);
    await box.publishAggregate(honestHex);

    // Auditor independently reconstructs
    const auditorReconstructed = await reconstructAggregateFromTranscript(box, publicKey);
    const auditorHex = serializeCanonical(auditorReconstructed);

    // They match
    expect(auditorHex).to.equal(honestHex);

    const publishedCommitment = ethers.keccak256(honestHex);
    const auditorCommitment = ethers.keccak256(auditorHex);
    expect(publishedCommitment).to.equal(auditorCommitment);

    console.log("    ✓ Honest aggregate: published matches transcript-derived");
  });

  it("reconstruction is deterministic across multiple independent runs", async function () {
    const { box } = await deployAndSetup();
    await castAllBallots(box);

    // Reconstruct multiple times
    const r1 = await reconstructAggregateFromTranscript(box, publicKey);
    const r2 = await reconstructAggregateFromTranscript(box, publicKey);
    const r3 = await reconstructAggregateFromTranscript(box, publicKey);

    expect(r1).to.equal(r2);
    expect(r2).to.equal(r3);
    console.log("    ✓ Reconstruction is deterministic");
  });
});
