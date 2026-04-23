/**
 * End-to-end integration test: real Groth16 proof → real verifier contract → ballot acceptance.
 *
 * This test proves that the full pipeline works:
 *   1. Build a Poseidon Merkle tree of eligible voters
 *   2. Encrypt a vote with Paillier (simulated ciphertext for the test)
 *   3. Decompose the ciphertext into 32 × 192-bit limbs
 *   4. Generate a real Groth16 proof using the compiled circuit
 *   5. Deploy the real Groth16Verifier (NOT a mock)
 *   6. Submit the ballot on-chain and verify acceptance
 *   7. Demonstrate that ciphertext substitution is rejected
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import path from "path";
// @ts-expect-error — snarkjs has no type declarations
import * as snarkjs from "snarkjs";
// @ts-expect-error — circomlibjs has no type declarations
import { buildPoseidon } from "circomlibjs";

const CIRCUIT_WASM = path.resolve(
  __dirname,
  "../../circuits/build/CrossGroupBallot_js/CrossGroupBallot.wasm",
);
const CIRCUIT_ZKEY = path.resolve(
  __dirname,
  "../../circuits/build/circuit_final.zkey",
);

const TREE_DEPTH = 10;
const LIMB_COUNT = 32;
const LIMB_HEX = 48; // 192 bits = 48 hex chars

// ── Poseidon helpers (matching circomlib) ──────────────────────────────

let poseidon: any;

async function initPoseidon() {
  if (!poseidon) poseidon = await buildPoseidon();
  return poseidon;
}

async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const p = await initPoseidon();
  return BigInt(p.F.toString(p(inputs)));
}

// ── Merkle tree helpers ───────────────────────────────────────────────

async function buildTree(leaves: bigint[]) {
  const size = 2 ** TREE_DEPTH;
  const padded = [...leaves];
  while (padded.length < size) padded.push(0n);

  const levels: bigint[][] = [padded];
  let cur = padded;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2)
      next.push(await poseidonHash([cur[i], cur[i + 1]]));
    levels.push(next);
    cur = next;
  }
  return levels;
}

function getProof(levels: bigint[][], idx: number) {
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let i = idx;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const sib = i % 2 === 0 ? i + 1 : i - 1;
    pathElements.push(levels[d][sib]);
    pathIndices.push(i % 2);
    i = Math.floor(i / 2);
  }
  return { pathElements, pathIndices, root: levels[TREE_DEPTH][0] };
}

// ── Ciphertext / limb helpers ─────────────────────────────────────────

function ciphertextToLimbs(hex: string): string[] {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  const totalHex = LIMB_COUNT * LIMB_HEX;
  if (raw.length > totalHex) {
    throw new Error(`Ciphertext too large for canonical width: ${raw.length / 2} bytes > ${totalHex / 2} bytes`);
  }
  const padded = raw.padStart(totalHex, "0");
  return Array.from({ length: LIMB_COUNT }, (_, i) =>
    BigInt("0x" + padded.slice(i * LIMB_HEX, (i + 1) * LIMB_HEX)).toString(),
  );
}

async function computeVoteHash(hex: string): Promise<bigint> {
  let level = ciphertextToLimbs(hex).map(BigInt);
  while (level.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2)
      next.push(await poseidonHash([level[i], level[i + 1]]));
    level = next;
  }
  return level[0];
}

// ── Test suite ────────────────────────────────────────────────────────

describe("End-to-end: real Groth16 proof on real verifier", function () {
  this.timeout(120_000); // proof generation can take a minute

  const SECRET = 42n;
  const ADDRESS = 123456789n;
  // Canonical 768-byte ciphertext (fixed-width, matching contract requirement)
  const CIPHERTEXT_HEX =
    "0x" + "abcdef0123456789".repeat(96); // 1536 hex chars = 768 bytes

  let leaf: bigint;
  let voteHash: bigint;
  let treeLevels: bigint[][];

  before(async function () {
    // Pre-compute all Poseidon values
    leaf = await poseidonHash([ADDRESS, SECRET]);
    voteHash = await computeVoteHash(CIPHERTEXT_HEX);
    treeLevels = await buildTree([leaf]);
  });

  async function deployRealVerifier() {
    const [owner, voter] = await ethers.getSigners();

    // Deploy the REAL Groth16Verifier generated from the circuit
    const realVerifier = await ethers.deployContract("Groth16Verifier");

    // Deploy mock ballot-validity verifier (ballot validity is a separate concern)
    const validityVerifier = await ethers.deployContract("MockBallotValidityVerifier");

    const box = await ethers.deployContract("CrossGroupBallotBox", [
      await realVerifier.getAddress(),
      await validityVerifier.getAddress(),
      owner.address,
    ]);

    return { owner, voter, realVerifier, validityVerifier, box };
  }

  async function initElection(box: any) {
    const [owner] = await ethers.getSigners();
    // Register owner as committee member (threshold <= committeeSize)
    try { await box.registerCommitteeMember(owner.address); } catch { /* already registered */ }
    const root = treeLevels[TREE_DEPTH][0];
    const latest = await ethers.provider.getBlockNumber();
    await box.initElection({
      publicKey: "0x1234",
      merkleRoot: "0x" + root.toString(16).padStart(64, "0"),
      threshold: 1,
      votingDeadlineBlock: latest + 50,
      tallyDeadlineBlock: latest + 100,
    });
    return box.getTranscript();
  }

  async function finalizeActiveElection(box: any) {
    for (let i = 0; i < 52; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();
    const aggregate = "0x" + "ff".repeat(768);
    await box.publishAggregate(aggregate);
    const aggregateCommitment = ethers.keccak256(aggregate);
    await box.submitShare("0x1111", aggregateCommitment, ethers.keccak256("0xaa"));
    await box.finalize({ resultData: "0x01", aggregateCommitment });
  }

  async function generateRealProof(nullifierDomain: bigint) {
    const { pathElements, pathIndices, root } = getProof(treeLevels, 0);
    const ctLimbs = ciphertextToLimbs(CIPHERTEXT_HEX);
    const nullifier = await poseidonHash([SECRET, nullifierDomain]);

    const circuitInput = {
      secret: SECRET.toString(),
      address: ADDRESS.toString(),
      pathElements: pathElements.map((e) => e.toString()),
      pathIndices: pathIndices,
      root: root.toString(),
      nullifier: nullifier.toString(),
      nullifierDomain: nullifierDomain.toString(),
      voteHash: voteHash.toString(),
      ctLimbs,
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      CIRCUIT_WASM,
      CIRCUIT_ZKEY,
    );

    return { proof, publicSignals, nullifier };
  }

  function formatForSolidity(proof: any) {
    return {
      pA: [proof.pi_a[0], proof.pi_a[1]] as [string, string],
      pB: [
        [proof.pi_b[0][1], proof.pi_b[0][0]],
        [proof.pi_b[1][1], proof.pi_b[1][0]],
      ] as [[string, string], [string, string]],
      pC: [proof.pi_c[0], proof.pi_c[1]] as [string, string],
    };
  }

  it("generates a real Groth16 proof and verifies it on-chain", async function () {
    const { box } = await deployRealVerifier();
    const transcript = await initElection(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    // Generate real proof
    const { proof, publicSignals, nullifier } = await generateRealProof(nullifierDomain);
    const sol = formatForSolidity(proof);

    const pubInputs = publicSignals.map(BigInt);

    // Cast ballot with REAL proof on REAL verifier
    const tx = await box.castBallot(
      CIPHERTEXT_HEX,
      sol.pA,
      sol.pB,
      sol.pC,
      "0xabcd", // validity proof bytes
      pubInputs,
    );

    const receipt = await tx.wait();

    // Verify ballot was accepted
    const ballot = await box.getBallot(0);
    expect(ballot.nullifier).to.equal(nullifier);

    // Record gas for the paper
    console.log(`    Gas used for castBallot (real Groth16, 36 inputs): ${receipt!.gasUsed.toString()}`);
  });

  it("rejects ciphertext substitution even with a real proof", async function () {
    const { box } = await deployRealVerifier();
    const transcript = await initElection(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    // Generate real proof for the original ciphertext
    const { proof, publicSignals } = await generateRealProof(nullifierDomain);
    const sol = formatForSolidity(proof);
    const pubInputs = publicSignals.map(BigInt);

    // Try to submit a DIFFERENT 768-byte ciphertext with the SAME proof
    const fakeCiphertext = "0x" + "1111111111111111".repeat(96);

    await expect(
      box.castBallot(
        fakeCiphertext,
        sol.pA,
        sol.pB,
        sol.pC,
        "0xabcd",
        pubInputs,
      ),
    ).to.be.revertedWithCustomError(box, "InvalidPublicInputs");
  });

  it("rejects reusing a proof from a finalized election in the next election", async function () {
    const { box } = await deployRealVerifier();
    const firstTranscript = await initElection(box);
    const firstNullifierDomain = BigInt(firstTranscript.params.nullifierDomain);

    const firstProofPackage = await generateRealProof(firstNullifierDomain);
    const firstSolidityProof = formatForSolidity(firstProofPackage.proof);
    const firstPublicInputs = firstProofPackage.publicSignals.map(BigInt);

    await finalizeActiveElection(box);

    // Start the next election with the same Merkle root but a fresh nullifier domain.
    const root = treeLevels[TREE_DEPTH][0];
    const latest = await ethers.provider.getBlockNumber();
    await box.initElection({
      publicKey: "0x1234",
      merkleRoot: "0x" + root.toString(16).padStart(64, "0"),
      threshold: 1,
      votingDeadlineBlock: latest + 50,
      tallyDeadlineBlock: latest + 100,
    });
    const secondTranscript = await box.getTranscript();
    expect(secondTranscript.params.nullifierDomain).to.not.equal(firstTranscript.params.nullifierDomain);

    await expect(
      box.castBallot(
        CIPHERTEXT_HEX,
        firstSolidityProof.pA,
        firstSolidityProof.pB,
        firstSolidityProof.pC,
        "0xabcd",
        firstPublicInputs,
      ),
    ).to.be.revertedWithCustomError(box, "InvalidPublicInputs");
  });

  it("accepts the same voter across two elections with fresh nullifiers", async function () {
    const { box } = await deployRealVerifier();

    const firstTranscript = await initElection(box);
    const firstNullifierDomain = BigInt(firstTranscript.params.nullifierDomain);
    const firstProofPackage = await generateRealProof(firstNullifierDomain);
    const firstSolidityProof = formatForSolidity(firstProofPackage.proof);
    const firstPublicInputs = firstProofPackage.publicSignals.map(BigInt);

    await box.castBallot(
      CIPHERTEXT_HEX,
      firstSolidityProof.pA,
      firstSolidityProof.pB,
      firstSolidityProof.pC,
      "0xabcd",
      firstPublicInputs,
    );

    const firstBallot = await box.getBallot(0);
    expect(firstBallot.nullifier).to.equal(firstProofPackage.nullifier);

    await finalizeActiveElection(box);

    const root = treeLevels[TREE_DEPTH][0];
    const latest = await ethers.provider.getBlockNumber();
    await box.initElection({
      publicKey: "0x1234",
      merkleRoot: "0x" + root.toString(16).padStart(64, "0"),
      threshold: 1,
      votingDeadlineBlock: latest + 50,
      tallyDeadlineBlock: latest + 100,
    });

    const secondTranscript = await box.getTranscript();
    const secondNullifierDomain = BigInt(secondTranscript.params.nullifierDomain);
    expect(secondNullifierDomain).to.not.equal(firstNullifierDomain);

    const secondProofPackage = await generateRealProof(secondNullifierDomain);
    expect(secondProofPackage.nullifier).to.not.equal(firstProofPackage.nullifier);

    const secondSolidityProof = formatForSolidity(secondProofPackage.proof);
    const secondPublicInputs = secondProofPackage.publicSignals.map(BigInt);

    await box.castBallot(
      CIPHERTEXT_HEX,
      secondSolidityProof.pA,
      secondSolidityProof.pB,
      secondSolidityProof.pC,
      "0xabcd",
      secondPublicInputs,
    );

    const secondBallot = await box.getBallot(0);
    expect(secondBallot.nullifier).to.equal(secondProofPackage.nullifier);
    expect(secondBallot.nullifier).to.not.equal(firstBallot.nullifier);
  });

  it("rejects a proof with tampered public inputs (wrong root)", async function () {
    const { box } = await deployRealVerifier();
    const transcript = await initElection(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    const { proof, publicSignals } = await generateRealProof(nullifierDomain);
    const sol = formatForSolidity(proof);
    const pubInputs = publicSignals.map(BigInt);

    // Tamper with root
    pubInputs[0] = 999n;

    await expect(
      box.castBallot(
        CIPHERTEXT_HEX,
        sol.pA,
        sol.pB,
        sol.pC,
        "0xabcd",
        pubInputs,
      ),
    ).to.be.revertedWithCustomError(box, "InvalidPublicInputs");
  });

  it("rejects a forged proof (wrong proof values)", async function () {
    const { box } = await deployRealVerifier();
    const transcript = await initElection(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    const { proof, publicSignals } = await generateRealProof(nullifierDomain);
    const pubInputs = publicSignals.map(BigInt);

    // Use garbage proof points
    const badProof = {
      pA: ["1", "2"] as [string, string],
      pB: [["1", "2"], ["3", "4"]] as [[string, string], [string, string]],
      pC: ["1", "2"] as [string, string],
    };

    // This should revert — either the verifier returns false or the precompile fails
    await expect(
      box.castBallot(
        CIPHERTEXT_HEX,
        badProof.pA,
        badProof.pB,
        badProof.pC,
        "0xabcd",
        pubInputs,
      ),
    ).to.be.reverted;
  });

  it("records a smoke-trace gas profile for core operations", async function () {
    const { box, owner } = await deployRealVerifier();
    const [, signer1] = await ethers.getSigners();

    // Register committee member BEFORE starting election
    await box.registerCommitteeMember(signer1.address);

    // Measure initElection gas
    const root = treeLevels[TREE_DEPTH][0];
    const latest = await ethers.provider.getBlockNumber();
    const initTx = await box.initElection({
      publicKey: "0x1234",
      merkleRoot: "0x" + root.toString(16).padStart(64, "0"),
      threshold: 1,
      votingDeadlineBlock: latest + 50,
      tallyDeadlineBlock: latest + 100,
    });
    const initReceipt = await initTx.wait();
    console.log(`    Gas: initElection = ${initReceipt!.gasUsed.toString()}`);
    const transcript = await box.getTranscript();
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    // Cast ballot
    const { proof, publicSignals } = await generateRealProof(nullifierDomain);
    const sol = formatForSolidity(proof);
    const pubInputs = publicSignals.map(BigInt);

    const castTx = await box.castBallot(
      CIPHERTEXT_HEX, sol.pA, sol.pB, sol.pC, "0xabcd", pubInputs,
    );
    const castReceipt = await castTx.wait();
    console.log(`    Gas: castBallot (real proof) = ${castReceipt!.gasUsed.toString()}`);

    // Close voting
    for (let i = 0; i < 52; i++) await ethers.provider.send("evm_mine", []);
    const closeTx = await box.closeVoting();
    const closeReceipt = await closeTx.wait();
    console.log(`    Gas: closeVoting = ${closeReceipt!.gasUsed.toString()}`);

    // Publish aggregate (canonical 768-byte width, matching ballot serialization)
    const aggregate = "0x" + "ff".repeat(768);
    const aggTx = await box.publishAggregate(aggregate);
    const aggReceipt = await aggTx.wait();
    console.log(`    Gas: publishAggregate = ${aggReceipt!.gasUsed.toString()}`);

    // Submit share with a tiny mock payload.
    // Production-width share gas is measured by scripts/gas-benchmark.ts.
    const aggCommitment = ethers.keccak256(aggregate);
    const shareTx = await box.connect(signer1).submitShare(
      "0x1111", aggCommitment, ethers.keccak256("0xaa"),
    );
    const shareReceipt = await shareTx.wait();
    console.log(`    Gas: submitShare (mock payload smoke trace) = ${shareReceipt!.gasUsed.toString()}`);

    // Finalize
    const finTx = await box.finalize({ resultData: "0x0102", aggregateCommitment: aggCommitment });
    const finReceipt = await finTx.wait();
    console.log(`    Gas: finalize = ${finReceipt!.gasUsed.toString()}`);

    expect(castReceipt!.gasUsed).to.be.greaterThan(0);
  });
});
