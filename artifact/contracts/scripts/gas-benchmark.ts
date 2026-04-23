import fs from "fs";
import path from "path";
import { ethers } from "hardhat";
// @ts-expect-error — snarkjs has no type declarations
import * as snarkjs from "snarkjs";
// @ts-expect-error — circomlibjs has no type declarations
import { buildPoseidon } from "circomlibjs";

const repoRoot = path.resolve(__dirname, "../../..");
const fixturePath = path.resolve(repoRoot, "artifact/experiments/results/production-fixture-3072.json");
const outputPath = path.resolve(repoRoot, "artifact/experiments/results/contract-gas-benchmarks.json");
const CIRCUIT_WASM = path.resolve(repoRoot, "artifact/circuits/build/CrossGroupBallot_js/CrossGroupBallot.wasm");
const CIRCUIT_ZKEY = path.resolve(repoRoot, "artifact/circuits/build/circuit_final.zkey");
const TREE_DEPTH = 10;
const CIPHERTEXT_BYTES = 768;

let poseidon: any;

async function initPoseidon() {
  if (!poseidon) poseidon = await buildPoseidon();
  return poseidon;
}

async function hash(inputs: bigint[]): Promise<bigint> {
  const p = await initPoseidon();
  return BigInt(p.F.toString(p(inputs)));
}

async function buildTree(leaves: bigint[]) {
  const size = 2 ** TREE_DEPTH;
  const padded = [...leaves];
  while (padded.length < size) padded.push(0n);
  const levels: bigint[][] = [padded];
  let cur = padded;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) next.push(await hash([cur[i], cur[i + 1]]));
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
    pathElements.push(levels[d][i % 2 === 0 ? i + 1 : i - 1]);
    pathIndices.push(i % 2);
    i = Math.floor(i / 2);
  }
  return { pathElements, pathIndices, root: levels[TREE_DEPTH][0] };
}

function ciphertextToLimbs(hex: string): string[] {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (raw.length !== CIPHERTEXT_BYTES * 2) {
    throw new Error(`Expected canonical 768-byte ciphertext, got ${raw.length / 2} bytes`);
  }
  return Array.from({ length: 32 }, (_, i) =>
    BigInt("0x" + raw.slice(i * 48, (i + 1) * 48)).toString(),
  );
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

async function generateBallotProof(
  secret: bigint,
  address: bigint,
  nullifierDomain: bigint,
  ctHex: string,
  treeLevels: bigint[][],
  leafIndex: number,
) {
  const nullifier = await hash([secret, nullifierDomain]);
  const voteHash = await computeVoteHash(ctHex);
  const { pathElements, pathIndices, root } = getProof(treeLevels, leafIndex);
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

function formatProof(proof: any) {
  return {
    pA: [proof.pi_a[0], proof.pi_a[1]] as [string, string],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ] as [[string, string], [string, string]],
    pC: [proof.pi_c[0], proof.pi_c[1]] as [string, string],
  };
}

function nonZeroByteDensity(hex: string) {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  let nonZero = 0;
  for (let i = 0; i < raw.length; i += 2) {
    if (raw.slice(i, i + 2) !== "00") nonZero++;
  }
  return {
    nonZeroBytes: nonZero,
    totalBytes: raw.length / 2,
    ratio: Number((nonZero / (raw.length / 2)).toFixed(4)),
  };
}

async function deployFreshBox() {
  const [owner] = await ethers.getSigners();
  const realVerifier = await ethers.deployContract("Groth16Verifier");
  const validityVerifier = await ethers.deployContract("MockBallotValidityVerifier");
  const box = await ethers.deployContract("CrossGroupBallotBox", [
    await realVerifier.getAddress(),
    await validityVerifier.getAddress(),
    owner.address,
  ]);
  return { box, owner };
}

async function main() {
  if (!fs.existsSync(fixturePath)) {
    throw new Error(`Missing ${fixturePath}. Run 'yarn bench:production' first.`);
  }

  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const [owner, cm1, cm2] = await ethers.getSigners();
  const voter1 = {
    secret: BigInt(`0x${fixture.voters[0].secretHex}`),
    address: BigInt(`0x${fixture.voters[0].addressHex}`),
    ciphertextHex: fixture.voters[0].ciphertextHex as string,
  };
  const voter2 = {
    secret: BigInt(`0x${fixture.voters[1].secretHex}`),
    address: BigInt(`0x${fixture.voters[1].addressHex}`),
    ciphertextHex: fixture.voters[1].ciphertextHex as string,
  };
  const denseCiphertext = `0x${"ff".repeat(CIPHERTEXT_BYTES)}`;

  const leaf1 = await hash([voter1.address, voter1.secret]);
  const leaf2 = await hash([voter2.address, voter2.secret]);
  const treeLevels = await buildTree([leaf1, leaf2]);
  const root = treeLevels[TREE_DEPTH][0];
  const publicKeyHex = `0x${fixture.publicKey.n.padStart(
    fixture.publicKey.n.length + (fixture.publicKey.n.length % 2),
    "0",
  )}`;

  const { box } = await deployFreshBox();
  await box.registerCommitteeMember(cm1.address);
  await box.registerCommitteeMember(cm2.address);

  const latest = await ethers.provider.getBlockNumber();
  const initTx = await box.initElection({
    publicKey: publicKeyHex,
    merkleRoot: `0x${root.toString(16).padStart(64, "0")}`,
    threshold: 2,
    votingDeadlineBlock: latest + 50,
    tallyDeadlineBlock: latest + 100,
  });
  const initReceipt = await initTx.wait();
  const transcript = await box.getTranscript();
  const nullifierDomain = BigInt(transcript.params.nullifierDomain);

  const realBallot1 = await generateBallotProof(
    voter1.secret,
    voter1.address,
    nullifierDomain,
    voter1.ciphertextHex,
    treeLevels,
    0,
  );
  const realProof1 = formatProof(realBallot1.proof);
  const realSignals1 = realBallot1.publicSignals.map(BigInt);

  const realBallot2 = await generateBallotProof(
    voter2.secret,
    voter2.address,
    nullifierDomain,
    voter2.ciphertextHex,
    treeLevels,
    1,
  );
  const realProof2 = formatProof(realBallot2.proof);
  const realSignals2 = realBallot2.publicSignals.map(BigInt);
  const castRealTx1 = await box.castBallot(
    voter1.ciphertextHex,
    realProof1.pA,
    realProof1.pB,
    realProof1.pC,
    "0xabcd",
    realSignals1,
  );
  const castRealReceipt1 = await castRealTx1.wait();

  const castRealTx2 = await box.castBallot(
    voter2.ciphertextHex,
    realProof2.pA,
    realProof2.pB,
    realProof2.pC,
    "0xabcd",
    realSignals2,
  );
  const castRealReceipt2 = await castRealTx2.wait();

  for (let i = 0; i < 52; i++) await ethers.provider.send("evm_mine", []);
  const closeTx = await box.closeVoting();
  const closeReceipt = await closeTx.wait();

  const publishTx = await box.publishAggregate(fixture.aggregateHex);
  const publishReceipt = await publishTx.wait();

  const aggregateCommitment = ethers.keccak256(fixture.aggregateHex);
  const share1Meta = ethers.keccak256(fixture.shares[0].shareHex);
  const share2Meta = ethers.keccak256(fixture.shares[1].shareHex);

  const shareTx1 = await box.connect(cm1).submitShare(fixture.shares[0].shareHex, aggregateCommitment, share1Meta);
  const shareReceipt1 = await shareTx1.wait();
  const shareTx2 = await box.connect(cm2).submitShare(fixture.shares[1].shareHex, aggregateCommitment, share2Meta);
  const shareReceipt2 = await shareTx2.wait();

  const finalizeTx = await box.finalize({
    resultData: "0x01",
    aggregateCommitment,
  });
  const finalizeReceipt = await finalizeTx.wait();

  const { box: denseBox } = await deployFreshBox();
  await denseBox.registerCommitteeMember(owner.address);
  const denseLatest = await ethers.provider.getBlockNumber();
  await denseBox.initElection({
    publicKey: publicKeyHex,
    merkleRoot: `0x${root.toString(16).padStart(64, "0")}`,
    threshold: 1,
    votingDeadlineBlock: denseLatest + 50,
    tallyDeadlineBlock: denseLatest + 100,
  });
  const denseTranscript = await denseBox.getTranscript();
  const denseNullifierDomain = BigInt(denseTranscript.params.nullifierDomain);
  const denseProof = await generateBallotProof(
    voter1.secret,
    voter1.address,
    denseNullifierDomain,
    denseCiphertext,
    treeLevels,
    0,
  );
  const denseSolidityProof = formatProof(denseProof.proof);
  const denseCastTx = await denseBox.castBallot(
    denseCiphertext,
    denseSolidityProof.pA,
    denseSolidityProof.pB,
    denseSolidityProof.pC,
    "0xabcd",
    denseProof.publicSignals.map(BigInt),
  );
  const denseCastReceipt = await denseCastTx.wait();

  const result = {
    benchmark: "contract-gas-benchmarks",
    generatedAt: new Date().toISOString(),
    fixturePath: path.relative(repoRoot, fixturePath),
    parameters: {
      modulusBits: fixture.keyBits,
      canonicalCiphertextBytes: CIPHERTEXT_BYTES,
      threshold: 2,
    },
    payloadDensity: {
      real3072Ciphertext: nonZeroByteDensity(voter1.ciphertextHex),
      denseSyntheticCiphertext: nonZeroByteDensity(denseCiphertext),
      realShare: nonZeroByteDensity(fixture.shares[0].shareHex),
      aggregate: nonZeroByteDensity(fixture.aggregateHex),
    },
    gas: {
      initElection: Number(initReceipt!.gasUsed),
      castBallotProductionReal3072: Number(castRealReceipt1!.gasUsed),
      castBallotProductionReal3072SecondBallot: Number(castRealReceipt2!.gasUsed),
      castBallotDenseSynthetic: Number(denseCastReceipt!.gasUsed),
      closeVoting: Number(closeReceipt!.gasUsed),
      publishAggregateReal3072: Number(publishReceipt!.gasUsed),
      submitShareReal3072: Number(shareReceipt1!.gasUsed),
      submitShareReal3072SecondShare: Number(shareReceipt2!.gasUsed),
      finalize: Number(finalizeReceipt!.gasUsed),
    },
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
