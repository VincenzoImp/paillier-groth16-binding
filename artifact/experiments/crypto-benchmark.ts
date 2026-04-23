/**
 * Crypto Performance Benchmarks for On-Chain Election Integrity.
 *
 * Measures client-side cryptographic operation timings including:
 * - Threshold Paillier key generation
 * - Vote encryption with CDS OR-proofs
 * - Merkle tree construction (Poseidon hash)
 * - Merkle proof generation
 * - Decryption share with DLEQ proof
 */

import { generateThresholdKeys } from "../crypto/paillier/keygen.js";
import { encryptVoteWithProof } from "../crypto/paillier/encrypt.js";
import { createDecryptionShareWithProof } from "../crypto/paillier/threshold.js";
import { buildMerkleTree, computeLeaf, getMerkleProof } from "../crypto/zkp/merkle.js";

async function benchmark() {
  console.log("=== Crypto Performance Benchmarks ===\n");

  // ─── 1. Key Generation ──────────────────────────────────────────────
  // Use 512-bit keys for benchmark speed. Production uses 3072-bit.
  console.log("1. Threshold Paillier Key Generation (512-bit, 3-of-5)...");
  const t0 = performance.now();
  const keySet = generateThresholdKeys(5, 3, 512);
  const keygenTime = performance.now() - t0;
  console.log(`   Key generation (512-bit, 3-of-5): ${keygenTime.toFixed(0)}ms`);

  // ─── 2. Vote Encryption with CDS OR-proof ──────────────────────────
  console.log("\n2. Vote Encryption + CDS OR-proof (2 candidates)...");
  const t1 = performance.now();
  const result = encryptVoteWithProof(keySet.publicKey, { Alice: 1, Bob: 0 });
  const encryptTime = performance.now() - t1;
  console.log(`   Vote encryption + CDS proof (2 candidates): ${encryptTime.toFixed(0)}ms`);

  // ─── 3. Merkle Tree Construction ────────────────────────────────────
  console.log("\n3. Merkle Tree Construction (1024 leaves, Poseidon hash)...");
  const leaves: bigint[] = [];
  for (let i = 0; i < 1024; i++) {
    leaves.push(await computeLeaf(BigInt(i + 1), BigInt(i * 1000 + 42)));
  }
  console.log("   Leaves computed. Building tree...");
  const t2 = performance.now();
  const tree = await buildMerkleTree(leaves);
  const treeTime = performance.now() - t2;
  console.log(`   Merkle tree (1024 leaves): ${treeTime.toFixed(0)}ms`);

  // ─── 4. Merkle Proof Generation ─────────────────────────────────────
  console.log("\n4. Merkle Proof Generation...");
  const t3 = performance.now();
  const proof = getMerkleProof(tree, 0);
  const proofTime = performance.now() - t3;
  console.log(`   Merkle proof generation: ${proofTime.toFixed(0)}ms`);
  console.log(`   Proof path length: ${proof.pathElements.length}`);

  // ─── 5. Decryption Share with DLEQ Proof ────────────────────────────
  console.log("\n5. Decryption Share + DLEQ Proof...");
  const ciphertext = result.ballot.candidateCiphertexts.get("Alice")!;
  const vi = keySet.verificationKeys.find(
    (vk) => vk.index === keySet.keyShares[0].index
  )!.vi;
  const t4 = performance.now();
  const shareResult = createDecryptionShareWithProof(
    keySet.keyShares[0],
    ciphertext,
    keySet.publicKey,
    keySet.totalShares,
    keySet.v,
    vi
  );
  const shareTime = performance.now() - t4;
  console.log(`   Decryption share + DLEQ proof: ${shareTime.toFixed(0)}ms`);

  // ─── 6. 2048-bit Key Generation + Encryption ─────────────────────────
  // 3072-bit safe prime generation can take >30 minutes. We benchmark
  // 2048-bit as a practical upper data point (still slow).
  console.log("\n6. 2048-bit Key Generation + Encryption...");
  const t2048_start = performance.now();
  const keySet2048 = generateThresholdKeys(5, 3, 2048);
  const keygen2048Time = performance.now() - t2048_start;
  console.log(`   Key generation (2048-bit, 3-of-5): ${keygen2048Time.toFixed(0)}ms`);

  const t2048_enc = performance.now();
  encryptVoteWithProof(keySet2048.publicKey, { Alice: 1, Bob: 0 });
  const encrypt2048Time = performance.now() - t2048_enc;
  console.log(`   Vote encryption + CDS proof (2048-bit): ${encrypt2048Time.toFixed(0)}ms`);

  // ─── Summary ────────────────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║              CRYPTO BENCHMARK SUMMARY                       ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log(`║ Key generation (512-bit, 3-of-5)      ${keygenTime.toFixed(0).padStart(8)}ms            ║`);
  console.log(`║ Vote encryption + CDS proof (2 cand)  ${encryptTime.toFixed(0).padStart(8)}ms            ║`);
  console.log(`║ Merkle tree (1024 leaves)              ${treeTime.toFixed(0).padStart(8)}ms            ║`);
  console.log(`║ Merkle proof generation                ${proofTime.toFixed(0).padStart(8)}ms            ║`);
  console.log(`║ Decryption share + DLEQ proof          ${shareTime.toFixed(0).padStart(8)}ms            ║`);
  console.log(`║ Key generation (2048-bit, 3-of-5)     ${keygen2048Time.toFixed(0).padStart(8)}ms            ║`);
  console.log(`║ Vote encryption + CDS proof (2048-bit) ${encrypt2048Time.toFixed(0).padStart(7)}ms            ║`);
  console.log("╚══════════════════════════════════════════════════════════════╝");

  console.log("\n=== Done ===");
}

benchmark().catch(console.error);
