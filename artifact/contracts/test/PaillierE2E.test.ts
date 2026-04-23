/**
 * Real Paillier E2E test: uses the actual @cgbl/crypto threshold Paillier
 * library to encrypt votes, serialize to 768-byte canonical form, generate
 * real Groth16 proofs, submit BOTH ballots on-chain, then exercise the full
 * contract tally path (publishAggregate → submitShare → finalize) with
 * real homomorphic aggregation and real threshold decryption.
 *
 * This test uses 512-bit keys for test speed (not deployment-strength).
 * It demonstrates pipeline interoperability, not production parameters.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import path from "path";
// @ts-expect-error — no types
import * as snarkjs from "snarkjs";
// @ts-expect-error — no types
import { buildPoseidon } from "circomlibjs";

// Import the REAL Paillier library from the crypto workspace's compiled output
const cryptoPath = path.resolve(__dirname, "../../crypto/dist/paillier/index.js");
let generateThresholdKeys: any;
let encryptValue: any;
let homomorphicAdd: any;
let createDecryptionShare: any;
let combineDecryptionShares: any;

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
    pathIndices.push(i % 2);
    i = Math.floor(i / 2);
  }
  return { pathElements, pathIndices, root: levels[TREE_DEPTH][0] };
}

function serializeCanonical(c: bigint): string {
  const hex = c.toString(16);
  if (hex.length > CIPHERTEXT_BYTES * 2)
    throw new Error(`Ciphertext too large: ${Math.ceil(hex.length / 2)} bytes`);
  return "0x" + hex.padStart(CIPHERTEXT_BYTES * 2, "0");
}

function ciphertextToLimbs(hex: string): string[] {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (raw.length !== CIPHERTEXT_BYTES * 2) throw new Error("not canonical width");
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
  const ctLimbs = ciphertextToLimbs(ctHex);

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      secret: secret.toString(),
      address: address.toString(),
      pathElements: pathElements.map((e: bigint) => e.toString()),
      pathIndices,
      root: root.toString(),
      nullifier: nullifier.toString(),
      nullifierDomain: nullifierDomain.toString(),
      voteHash: voteHash.toString(),
      ctLimbs,
    },
    CIRCUIT_WASM,
    CIRCUIT_ZKEY,
  );

  return { proof, publicSignals, nullifier };
}

describe("Real Paillier Library E2E: two ballots on-chain → contract tally path → threshold decrypt", function () {
  this.timeout(180_000);

  before(async function () {
    const crypto = await import(cryptoPath);
    generateThresholdKeys = crypto.generateThresholdKeys;
    encryptValue = crypto.encryptValue;
    homomorphicAdd = crypto.homomorphicAdd;
    createDecryptionShare = crypto.createDecryptionShare;
    combineDecryptionShares = crypto.combineDecryptionShares;
  });

  it("two voters cast real Paillier ballots on-chain, then publishAggregate → submitShare → finalize → threshold decrypt", async function () {
    // ── 1. Threshold Paillier keygen (real library, 512-bit for speed) ──
    const keySet = generateThresholdKeys(3, 2, 512);
    const { publicKey, keyShares } = keySet;
    console.log(`    Paillier modulus bits: ${publicKey.n.toString(2).length}, threshold: 2-of-3`);

    // ── 2. Two voters encrypt with real Paillier ──
    const vote1Raw = encryptValue(publicKey, 1n); // voter 1: candidate 1
    const vote2Raw = encryptValue(publicKey, 0n); // voter 2: candidate 0
    const ct1Hex = serializeCanonical(vote1Raw);
    const ct2Hex = serializeCanonical(vote2Raw);

    // ── 3. Build Merkle tree for two voters ──
    const S1 = 11111n, A1 = 22222n;
    const S2 = 33333n, A2 = 44444n;
    const leaf1 = await hash([A1, S1]);
    const leaf2 = await hash([A2, S2]);
    const treeLevels = await buildTree([leaf1, leaf2]);
    const root = treeLevels[TREE_DEPTH][0];

    // ── 4. Deploy contract with real verifier ──
    const realVerifier = await ethers.deployContract("Groth16Verifier");
    const validityVerifier = await ethers.deployContract("MockBallotValidityVerifier");
    const [owner, cm1, cm2, cm3] = await ethers.getSigners();
    const box = await ethers.deployContract("CrossGroupBallotBox", [
      await realVerifier.getAddress(),
      await validityVerifier.getAddress(),
      owner.address,
    ]);

    // Register 3 committee members (matching 2-of-3 threshold key holders)
    await box.registerCommitteeMember(cm1.address);
    await box.registerCommitteeMember(cm2.address);
    await box.registerCommitteeMember(cm3.address);

    const latest = await ethers.provider.getBlockNumber();
    const nHex = publicKey.n.toString(16);
    await box.initElection({
      publicKey: "0x" + nHex.padStart(nHex.length + (nHex.length % 2), "0"),
      merkleRoot: "0x" + root.toString(16).padStart(64, "0"),
      threshold: 2,
      votingDeadlineBlock: latest + 50,
      tallyDeadlineBlock: latest + 100,
    });
    const transcriptAfterInit = await box.getTranscript();
    const nullifierDomain = BigInt(transcriptAfterInit.params.nullifierDomain);

    // ── 5. Generate real Groth16 proofs for BOTH voters ──
    const ballot1 = await generateBallotProof(S1, A1, nullifierDomain, ct1Hex, treeLevels, 0);
    const ballot2 = await generateBallotProof(S2, A2, nullifierDomain, ct2Hex, treeLevels, 1);
    console.log("    Both Groth16 proofs generated");

    // ── 6. Cast BOTH ballots on-chain with real proofs ──
    const sol1 = formatProof(ballot1.proof);
    await box.castBallot(
      ct1Hex, sol1.pA, sol1.pB, sol1.pC, "0xabcd",
      ballot1.publicSignals.map(BigInt),
    );

    const sol2 = formatProof(ballot2.proof);
    await box.castBallot(
      ct2Hex, sol2.pA, sol2.pB, sol2.pC, "0xabcd",
      ballot2.publicSignals.map(BigInt),
    );

    // Verify both ballots accepted
    const b0 = await box.getBallot(0);
    const b1 = await box.getBallot(1);
    expect(b0.nullifier).to.equal(ballot1.nullifier);
    expect(b1.nullifier).to.equal(ballot2.nullifier);
    console.log("    Both ballots accepted on-chain");

    // ── 7. Close voting ──
    for (let i = 0; i < 52; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();

    // ── 8. Reconstruct aggregate from contract transcript, NOT local vars ──
    // Read the accepted ciphertext bytes back from the contract, parse them
    // to bigints, and aggregate. This proves the tally is derived from the
    // on-chain record, not from the prover's local memory.
    const onChainBallot0 = await box.getBallot(0);
    const onChainBallot1 = await box.getBallot(1);
    const ctFromChain0 = BigInt(onChainBallot0.ciphertext);
    const ctFromChain1 = BigInt(onChainBallot1.ciphertext);

    // Sanity: the on-chain ciphertexts match what we submitted
    expect(ctFromChain0).to.equal(vote1Raw);
    expect(ctFromChain1).to.equal(vote2Raw);

    const aggregateBigInt = homomorphicAdd(publicKey, ctFromChain0, ctFromChain1);
    const aggregateHex = serializeCanonical(aggregateBigInt);
    console.log("    Aggregate reconstructed from on-chain ballot records");

    // ── 9. publishAggregate on-chain ──
    await box.publishAggregate(aggregateHex);
    const aggregateCommitment = ethers.keccak256(aggregateHex);
    console.log("    Aggregate published on-chain");

    // ── 10. submitShare from 2 of 3 committee members ──
    const share1 = createDecryptionShare(keyShares[0], aggregateBigInt, 3);
    const share2 = createDecryptionShare(keyShares[1], aggregateBigInt, 3);

    // Serialize shares for on-chain recording
    const share1Hex = "0x" + share1.ci.toString(16).padStart(256, "0");
    const share2Hex = "0x" + share2.ci.toString(16).padStart(256, "0");
    const meta1 = ethers.keccak256(ethers.toUtf8Bytes(`share-${share1.index}`));
    const meta2 = ethers.keccak256(ethers.toUtf8Bytes(`share-${share2.index}`));

    await box.connect(cm1).submitShare(share1Hex, aggregateCommitment, meta1);
    await box.connect(cm2).submitShare(share2Hex, aggregateCommitment, meta2);
    console.log("    2 decryption shares submitted on-chain");

    // ── 11. finalize on-chain ──
    const tallyResult = combineDecryptionShares([share1, share2], 2, 3, publicKey);
    const resultHex = "0x" + tallyResult.toString(16).padStart(2, "0");

    await box.finalize({ resultData: resultHex, aggregateCommitment });

    // ── 12. Verify final state ──
    const transcript = await box.getTranscript();
    expect(transcript.currentPhase).to.equal(3); // FINALIZED
    expect(transcript.ballotCount).to.equal(2);
    expect(transcript.shareCount).to.equal(2);
    expect(transcript.result.aggregateCommitment).to.equal(aggregateCommitment);

    // ── 13. Verify threshold decryption gives correct result ──
    expect(tallyResult).to.equal(1n); // 1 + 0 = 1
    console.log(`    Threshold decryption result: ${tallyResult} (1+0=1) ✓`);
    console.log("    ✓ Full pipeline: real keygen → 2× real encrypt → 2× on-chain castBallot → closeVoting → publishAggregate → 2× submitShare → finalize → threshold decrypt");
  });
});
