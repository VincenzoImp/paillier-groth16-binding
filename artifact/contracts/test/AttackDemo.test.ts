/**
 * Attack demonstration: ciphertext substitution on naive vs bound composition.
 *
 * This test file is the most important piece of artifact evidence for the paper.
 * It proves, on a real EVM with a real Groth16 verifier, that:
 *
 * 1. A naive contract that omits binding checks ACCEPTS a ballot with a
 *    substituted ciphertext and a reused proof.
 *
 * 2. The bound contract (CrossGroupBallotBox) REJECTS the exact same attack
 *    because the posted ciphertext bytes do not match the public limbs
 *    committed inside the proof.
 *
 * This is the operational proof of Proposition 1 and Theorem 1 in the paper.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import path from "path";
// @ts-expect-error — no types
import * as snarkjs from "snarkjs";
// @ts-expect-error — no types
import { buildPoseidon } from "circomlibjs";

const CIRCUIT_WASM = path.resolve(__dirname, "../../circuits/build/CrossGroupBallot_js/CrossGroupBallot.wasm");
const CIRCUIT_ZKEY = path.resolve(__dirname, "../../circuits/build/circuit_final.zkey");
const TREE_DEPTH = 10;

let poseidon: any;
async function initPoseidon() { if (!poseidon) poseidon = await buildPoseidon(); return poseidon; }
async function hash(inputs: bigint[]): Promise<bigint> {
  const p = await initPoseidon();
  return BigInt(p.F.toString(p(inputs)));
}

async function buildTree(leaves: bigint[]) {
  const size = 2 ** TREE_DEPTH;
  const padded = [...leaves]; while (padded.length < size) padded.push(0n);
  const levels: bigint[][] = [padded];
  let cur = padded;
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

function ciphertextToLimbs(hex: string): string[] {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = raw.padStart(1536, "0").slice(0, 1536);
  return Array.from({ length: 32 }, (_, i) =>
    BigInt("0x" + padded.slice(i * 48, (i + 1) * 48)).toString());
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

describe("Attack Demo: Naive vs Bound Composition", function () {
  this.timeout(120_000);

  const SECRET = 77n;
  const ADDRESS = 42n;
  const NAIVE_ELECTION_ID = 1n;
  // Canonical 768-byte ciphertexts (fixed-width, matching contract requirement)
  const VICTIM_CIPHERTEXT = "0x" + "aabbccdd".repeat(192);   // 4*192 = 768 bytes
  const ATTACKER_CIPHERTEXT = "0x" + "11223344".repeat(192); // different 768 bytes

  let treeLevels: bigint[][];
  let root: bigint;
  let voteHash: bigint;

  before(async function () {
    const leaf = await hash([ADDRESS, SECRET]);
    voteHash = await computeVoteHash(VICTIM_CIPHERTEXT);
    treeLevels = await buildTree([leaf]);
    root = treeLevels[TREE_DEPTH][0];
  });

  async function generateVictimProof(nullifierDomain: bigint) {
    const { pathElements, pathIndices } = getProof(treeLevels, 0);
    const ctLimbs = ciphertextToLimbs(VICTIM_CIPHERTEXT);
    const nullifier = await hash([SECRET, nullifierDomain]);

    const result = await snarkjs.groth16.fullProve(
      {
        secret: SECRET.toString(),
        address: ADDRESS.toString(),
        pathElements: pathElements.map(e => e.toString()),
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

    return { proof: result.proof, publicSignals: result.publicSignals, nullifier };
  }

  it("ATTACK SUCCEEDS on naive contract: substituted ciphertext accepted", async function () {
    // Deploy naive (insecure) contract with the REAL verifier
    const realVerifier = await ethers.deployContract("Groth16Verifier");
    const naive = await ethers.deployContract("NaiveBallotBox", [await realVerifier.getAddress()]);

    const rootHex = "0x" + root.toString(16).padStart(64, "0");
    await naive.startElection(NAIVE_ELECTION_ID, rootHex);

    const { proof: victimProof, publicSignals: victimPublicSignals, nullifier } = await generateVictimProof(1n);

    const sol = formatProof(victimProof);
    const pubInputs = victimPublicSignals.map(BigInt);

    // The attacker submits the VICTIM'S proof with a DIFFERENT ciphertext.
    // On the naive contract, this SUCCEEDS because there is no binding check.
    await expect(
      naive.castBallot(ATTACKER_CIPHERTEXT, sol.pA, sol.pB, sol.pC, pubInputs),
    ).to.emit(naive, "NaiveBallotAccepted");

    // Verify the ballot was stored with the ATTACKER'S ciphertext
    const ballot = await naive.ballots(0);
    expect(ballot.ciphertext).to.equal(ATTACKER_CIPHERTEXT);
    expect(ballot.nullifier).to.equal(nullifier);

    console.log("    ✗ NAIVE: Attacker's substituted ciphertext was ACCEPTED with victim's proof");
  });

  it("ATTACK FAILS on bound contract: substituted ciphertext rejected", async function () {
    // Deploy bound (secure) contract with the REAL verifier
    const realVerifier = await ethers.deployContract("Groth16Verifier");
    const validityVerifier = await ethers.deployContract("MockBallotValidityVerifier");
    const [owner] = await ethers.getSigners();
    const bound = await ethers.deployContract("CrossGroupBallotBox", [
      await realVerifier.getAddress(),
      await validityVerifier.getAddress(),
      owner.address,
    ]);

    await bound.registerCommitteeMember(owner.address);
    const rootHex = "0x" + root.toString(16).padStart(64, "0");
    const latest = await ethers.provider.getBlockNumber();
    await bound.initElection({
      publicKey: "0x1234",
      merkleRoot: rootHex,
      threshold: 1,
      votingDeadlineBlock: latest + 50,
      tallyDeadlineBlock: latest + 100,
    });
    const transcript = await bound.getTranscript();
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    const { proof: victimProof, publicSignals: victimPublicSignals } = await generateVictimProof(nullifierDomain);

    const sol = formatProof(victimProof);
    const pubInputs = victimPublicSignals.map(BigInt);

    // The attacker submits the VICTIM'S proof with a DIFFERENT ciphertext.
    // On the bound contract, this FAILS because the limbs don't match.
    await expect(
      bound.castBallot(
        ATTACKER_CIPHERTEXT,
        sol.pA, sol.pB, sol.pC,
        "0xabcd",
        pubInputs,
      ),
    ).to.be.revertedWithCustomError(bound, "InvalidPublicInputs");

    console.log("    ✓ BOUND: Attacker's substituted ciphertext was REJECTED by binding check");
  });

  it("victim's original ballot succeeds on bound contract", async function () {
    const realVerifier = await ethers.deployContract("Groth16Verifier");
    const validityVerifier = await ethers.deployContract("MockBallotValidityVerifier");
    const [owner] = await ethers.getSigners();
    const bound = await ethers.deployContract("CrossGroupBallotBox", [
      await realVerifier.getAddress(),
      await validityVerifier.getAddress(),
      owner.address,
    ]);

    await bound.registerCommitteeMember(owner.address);
    const rootHex = "0x" + root.toString(16).padStart(64, "0");
    const latest = await ethers.provider.getBlockNumber();
    await bound.initElection({
      publicKey: "0x1234",
      merkleRoot: rootHex,
      threshold: 1,
      votingDeadlineBlock: latest + 50,
      tallyDeadlineBlock: latest + 100,
    });
    const transcript = await bound.getTranscript();
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    const { proof: victimProof, publicSignals: victimPublicSignals } = await generateVictimProof(nullifierDomain);

    const sol = formatProof(victimProof);
    const pubInputs = victimPublicSignals.map(BigInt);

    // The victim's original ciphertext + proof SUCCEEDS because limbs match.
    await expect(
      bound.castBallot(
        VICTIM_CIPHERTEXT,
        sol.pA, sol.pB, sol.pC,
        "0xabcd",
        pubInputs,
      ),
    ).to.emit(bound, "BallotAccepted");

    console.log("    ✓ BOUND: Victim's original ballot was ACCEPTED correctly");
  });
});
