import { expect } from "chai";
import { ethers } from "hardhat";

const ROOT = "0x" + "11".repeat(32);
const ROOT_BIGINT = BigInt(ROOT);
const CIPHERTEXT_BYTES = 768;

// Canonical 768-byte ciphertexts for testing.
// After the injectivity fix, the contract requires exactly 768 bytes.
const CT_A = "0x" + "ab".repeat(CIPHERTEXT_BYTES);
const CT_B = "0x" + "cd".repeat(CIPHERTEXT_BYTES);

function ciphertextHexToLimbs(ciphertextHex: string): bigint[] {
  const hex = ciphertextHex.startsWith("0x") ? ciphertextHex.slice(2) : ciphertextHex;
  if (hex.length !== CIPHERTEXT_BYTES * 2) {
    throw new Error(`ciphertext must be exactly ${CIPHERTEXT_BYTES} bytes, got ${hex.length / 2}`);
  }
  const limbHex = 48;
  return Array.from({ length: 32 }, (_, i) => BigInt(`0x${hex.slice(i * limbHex, (i + 1) * limbHex)}`));
}

function buildPublicInputs(ciphertextHex: string, overrides?: Partial<{
  root: bigint;
  nullifier: bigint;
  nullifierDomain: bigint;
  voteHash: bigint;
}>): bigint[] {
  const limbs = ciphertextHexToLimbs(ciphertextHex);
  return [
    overrides?.root ?? ROOT_BIGINT,
    overrides?.nullifier ?? 7n,
    overrides?.nullifierDomain ?? 0n,
    overrides?.voteHash ?? 99n,
    ...limbs,
  ];
}

describe("CrossGroupBallotBox", function () {
  async function deployFixture() {
    const [owner, other, share1, share2] = await ethers.getSigners();

    const verifier = await ethers.deployContract("MockVerifier");
    const validityVerifier = await ethers.deployContract("MockBallotValidityVerifier");
    const box = await ethers.deployContract("CrossGroupBallotBox", [
      await verifier.getAddress(),
      await validityVerifier.getAddress(),
      owner.address,
    ]);

    return { owner, other, share1, share2, verifier, validityVerifier, box };
  }

  async function init(box: any, committeeMembers?: string[], threshold?: number) {
    const [owner] = await ethers.getSigners();
    const members = committeeMembers ?? [owner.address]; // default: owner is committee
    for (const m of members) {
      try { await box.registerCommitteeMember(m); } catch { /* already registered */ }
    }
    const latest = await ethers.provider.getBlockNumber();
    await box.initElection({
      publicKey: "0x1234",
      merkleRoot: ROOT,
      threshold: threshold ?? members.length,
      votingDeadlineBlock: latest + 10,
      tallyDeadlineBlock: latest + 25,
    });
    return box.getTranscript();
  }

  it("initializes the election with minimal parameters", async function () {
    const { box } = await deployFixture();
    const transcript = await init(box);
    expect(transcript.params.electionIndex).to.equal(1n);
    expect(transcript.params.nullifierDomain).to.not.equal(0n);
    expect(transcript.currentPhase).to.equal(1); // VOTING
  });

  it("accepts a ballot with matching limbs and a valid proof", async function () {
    const { box } = await deployFixture();
    const transcript = await init(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    await box.castBallot(
      CT_A,
      [0, 0],
      [[0, 0], [0, 0]],
      [0, 0],
      "0xabcd",
      buildPublicInputs(CT_A, { nullifierDomain }),
    );

    const ballot = await box.getBallot(0);
    expect(ballot.nullifier).to.equal(7n);
  });

  it("rejects non-canonical ciphertext length", async function () {
    const { box } = await deployFixture();
    const transcript = await init(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    // Short ciphertext — must be rejected
    await expect(
      box.castBallot(
        "0x1234", [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd",
        buildPublicInputs(CT_A, { nullifierDomain }),
      ),
    ).to.be.revertedWithCustomError(box, "InvalidCiphertext");
  });

  it("rejects duplicate nullifiers", async function () {
    const { box } = await deployFixture();
    const transcript = await init(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    const publicInputs = buildPublicInputs(CT_A, { nullifierDomain });
    await box.castBallot(CT_A, [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd", publicInputs);

    await expect(
      box.castBallot(
        CT_B, [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd",
        buildPublicInputs(CT_B, { nullifierDomain }),
      ),
    ).to.be.revertedWithCustomError(box, "NullifierAlreadySpent");
  });

  it("rejects root mismatches", async function () {
    const { box } = await deployFixture();
    const transcript = await init(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    await expect(
      box.castBallot(
        CT_A, [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd",
        buildPublicInputs(CT_A, { root: 22n, nullifierDomain }),
      ),
    ).to.be.revertedWithCustomError(box, "InvalidPublicInputs");
  });

  it("rejects ciphertext substitution through public limb mismatch", async function () {
    const { box } = await deployFixture();
    const transcript = await init(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);

    // Post CT_B but claim limbs of CT_A — must be rejected
    await expect(
      box.castBallot(
        CT_B, [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd",
        buildPublicInputs(CT_A, { nullifierDomain }),
      ),
    ).to.be.revertedWithCustomError(box, "InvalidPublicInputs");
  });

  it("rejects ballots when the verifier returns false", async function () {
    const { box, verifier } = await deployFixture();
    const transcript = await init(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);
    await verifier.setResult(false);

    await expect(
      box.castBallot(
        CT_A, [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd",
        buildPublicInputs(CT_A, { nullifierDomain }),
      ),
    ).to.be.revertedWithCustomError(box, "InvalidProof");
  });

  it("rejects ballots when the ballot-validity verifier returns false", async function () {
    const { box, validityVerifier } = await deployFixture();
    const transcript = await init(box);
    const nullifierDomain = BigInt(transcript.params.nullifierDomain);
    await validityVerifier.setResult(false);

    await expect(
      box.castBallot(
        CT_A, [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd",
        buildPublicInputs(CT_A, { nullifierDomain }),
      ),
    ).to.be.revertedWithCustomError(box, "InvalidValidityProof");
  });

  it("closes voting, publishes the aggregate, accepts shares, and finalizes", async function () {
    const { box, share1, share2 } = await deployFixture();
    const initialTranscript = await init(box, [share1.address, share2.address]);
    const nullifierDomain = BigInt(initialTranscript.params.nullifierDomain);

    await box.castBallot(
      CT_A, [0, 0], [[0, 0], [0, 0]], [0, 0], "0xabcd",
      buildPublicInputs(CT_A, { nullifierDomain }),
    );

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);

    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));

    const aggregateCommitment = ethers.keccak256("0x" + "be".repeat(768));

    await box.connect(share1).submitShare("0x1111", aggregateCommitment, ethers.keccak256("0xaa"));
    await box.connect(share2).submitShare("0x2222", aggregateCommitment, ethers.keccak256("0xbb"));

    await box.finalize({ resultData: "0x0102", aggregateCommitment });

    const finalTranscript = await box.getTranscript();
    expect(finalTranscript.currentPhase).to.equal(3); // FINALIZED
    expect(finalTranscript.shareCount).to.equal(2);
  });

  it("rejects finalization with insufficient shares", async function () {
    const { box, share1, share2 } = await deployFixture();
    await init(box, [share1.address, share2.address], 2);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);

    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));
    const aggregateCommitment = ethers.keccak256("0x" + "be".repeat(768));

    await box.connect(share1).submitShare("0x1111", aggregateCommitment, ethers.keccak256("0xaa"));

    await expect(
      box.finalize({ resultData: "0x0102", aggregateCommitment }),
    ).to.be.revertedWithCustomError(box, "InsufficientShares");
  });

  it("rejects zero share proof metadata", async function () {
    const { box, share1 } = await deployFixture();
    await init(box, [share1.address]);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));
    const aggregateCommitment = ethers.keccak256("0x" + "be".repeat(768));

    await expect(
      box.connect(share1).submitShare("0x1111", aggregateCommitment, ethers.ZeroHash),
    ).to.be.revertedWithCustomError(box, "InvalidShareProofMetadata");
  });

  it("rejects aggregate commitment mismatches during share submission", async function () {
    const { box, share1 } = await deployFixture();
    await init(box, [share1.address]);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));

    await expect(
      box.connect(share1).submitShare("0x1111", ethers.keccak256("0xdead"), ethers.keccak256("0xaa")),
    ).to.be.revertedWithCustomError(box, "AggregateCommitmentMismatch");
  });

  it("rejects share submission after the tally deadline", async function () {
    const { box, share1 } = await deployFixture();
    await init(box, [share1.address]);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));
    const aggregateCommitment = ethers.keccak256("0x" + "be".repeat(768));

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);

    await expect(
      box.connect(share1).submitShare("0x1111", aggregateCommitment, ethers.keccak256("0xaa")),
    ).to.be.revertedWithCustomError(box, "TallyClosed");
  });

  it("allows starting a new election after finalization", async function () {
    const { box, share1, share2 } = await deployFixture();
    await init(box, [share1.address, share2.address]);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));
    const aggregateCommitment = ethers.keccak256("0x" + "be".repeat(768));
    await box.connect(share1).submitShare("0x1111", aggregateCommitment, ethers.keccak256("0xaa"));
    await box.connect(share2).submitShare("0x2222", aggregateCommitment, ethers.keccak256("0xbb"));
    await box.finalize({ resultData: "0x01", aggregateCommitment });

    const latest = await ethers.provider.getBlockNumber();
    await box.initElection({
      publicKey: "0x99",
      merkleRoot: ROOT,
      threshold: 1,
      votingDeadlineBlock: latest + 5,
      tallyDeadlineBlock: latest + 10,
    });

    const transcript = await box.getTranscript();
    expect(transcript.params.electionIndex).to.equal(2n);
    expect(transcript.ballotCount).to.equal(0);
    expect(transcript.shareCount).to.equal(0);
  });

  it("derives distinct nullifier domains across consecutive elections", async function () {
    const { box } = await deployFixture();
    const first = await init(box);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));
    const aggregateCommitment = ethers.keccak256("0x" + "be".repeat(768));
    await box.submitShare("0x1111", aggregateCommitment, ethers.keccak256("0xaa"));
    await box.finalize({ resultData: "0x01", aggregateCommitment });

    const latest = await ethers.provider.getBlockNumber();
    await box.initElection({
      publicKey: "0x99",
      merkleRoot: ROOT,
      threshold: 1,
      votingDeadlineBlock: latest + 5,
      tallyDeadlineBlock: latest + 10,
    });

    const second = await box.getTranscript();
    expect(first.params.nullifierDomain).to.not.equal(second.params.nullifierDomain);
  });

  it("derives distinct nullifier domains for different contract deployments", async function () {
    const { box: boxA } = await deployFixture();
    const { box: boxB } = await deployFixture();

    const transcriptA = await init(boxA);
    const transcriptB = await init(boxB);

    expect(transcriptA.params.electionIndex).to.equal(1n);
    expect(transcriptB.params.electionIndex).to.equal(1n);
    expect(transcriptA.params.nullifierDomain).to.not.equal(transcriptB.params.nullifierDomain);
  });

  it("rejects share submission from non-committee member", async function () {
    const { box, other, share1 } = await deployFixture();
    await init(box, [share1.address]);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();
    await box.publishAggregate("0x" + "be".repeat(768));
    const aggregateCommitment = ethers.keccak256("0x" + "be".repeat(768));

    await expect(
      box.connect(other).submitShare("0x1111", aggregateCommitment, ethers.keccak256("0xaa")),
    ).to.be.revertedWithCustomError(box, "NotCommitteeMember");
  });

  it("rejects non-canonical aggregate length", async function () {
    const { box } = await deployFixture();
    await init(box);

    for (let i = 0; i < 12; i++) await ethers.provider.send("evm_mine", []);
    await box.closeVoting();

    // Short aggregate — must be rejected
    await expect(
      box.publishAggregate("0xbeef"),
    ).to.be.revertedWithCustomError(box, "InvalidAggregate");

    // Too long — must also be rejected
    await expect(
      box.publishAggregate("0x" + "be".repeat(769)),
    ).to.be.revertedWithCustomError(box, "InvalidAggregate");
  });

  it("rejects zero-address committee registration", async function () {
    const { box } = await deployFixture();

    await expect(
      box.registerCommitteeMember(ethers.ZeroAddress),
    ).to.be.revertedWithCustomError(box, "NotCommitteeMember");
  });
});
