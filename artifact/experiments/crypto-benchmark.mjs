import {
  generateThresholdKeys,
} from "../crypto/dist/paillier/keygen.js";
import {
  encryptVoteWithProof,
} from "../crypto/dist/paillier/encrypt.js";
import {
  createDecryptionShareWithProof,
} from "../crypto/dist/paillier/threshold.js";
import {
  buildMerkleTree,
  computeLeaf,
  getMerkleProof,
} from "../crypto/dist/zkp/merkle.js";

async function benchmark() {
  console.log("=== Crypto Performance Benchmarks ===\n");

  console.log("1. Threshold Paillier Key Generation (512-bit, 3-of-5)...");
  const t0 = performance.now();
  const keySet = generateThresholdKeys(5, 3, 512);
  const keygenTime = performance.now() - t0;
  console.log(`   Key generation (512-bit, 3-of-5): ${keygenTime.toFixed(0)}ms`);

  console.log("\n2. Vote Encryption + CDS OR-proof (2 candidates)...");
  const t1 = performance.now();
  const result = encryptVoteWithProof(keySet.publicKey, { Alice: 1, Bob: 0 });
  const encryptTime = performance.now() - t1;
  console.log(`   Vote encryption + CDS proof (2 candidates): ${encryptTime.toFixed(0)}ms`);

  console.log("\n3. Merkle Tree Construction (1024 leaves, Poseidon hash)...");
  const leaves = [];
  for (let i = 0; i < 1024; i++) {
    leaves.push(await computeLeaf(BigInt(i + 1), BigInt(i * 1000 + 42)));
  }
  const t2 = performance.now();
  const tree = await buildMerkleTree(leaves);
  const treeTime = performance.now() - t2;
  console.log(`   Merkle tree (1024 leaves): ${treeTime.toFixed(0)}ms`);

  console.log("\n4. Merkle Proof Generation...");
  const t3 = performance.now();
  const proof = getMerkleProof(tree, 0);
  const proofTime = performance.now() - t3;
  console.log(`   Merkle proof generation: ${proofTime.toFixed(0)}ms`);
  console.log(`   Proof path length: ${proof.pathElements.length}`);

  console.log("\n5. Decryption Share + DLEQ Proof...");
  const ciphertext = result.ballot.candidateCiphertexts.get("Alice");
  const vi = keySet.verificationKeys.find(
    vk => vk.index === keySet.keyShares[0].index,
  ).vi;
  const t4 = performance.now();
  createDecryptionShareWithProof(
    keySet.keyShares[0],
    ciphertext,
    keySet.publicKey,
    keySet.totalShares,
    keySet.v,
    vi,
  );
  const shareTime = performance.now() - t4;
  console.log(`   Decryption share + DLEQ proof: ${shareTime.toFixed(0)}ms`);
}

benchmark().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
