/**
 * Threshold Decryption — Shoup's Protocol for Paillier.
 *
 * Each key-holder computes a partial decryption share:
 *   c_i = c^{2 * delta * s_i} mod n²
 *
 * The combiner collects >= threshold shares, computes Lagrange
 * coefficients scaled by delta = l! (l = totalShares), and
 * reconstructs the plaintext:
 *
 *   cprime = product_i( c_i^{2 * lambda_i} ) mod n²
 *   where lambda_i = delta * product_{j!=i}( (j) / (j - i) )
 *
 *   plaintext = L(cprime) * (4 * delta²)^{-1} mod n
 *   where L(x) = (x - 1) / n
 */

import crypto from "crypto";
import type {
  PaillierPublicKey,
  KeyShare,
  DecryptionShare,
  VerificationKey,
  DLEQProof,
  DecryptionShareWithProof,
} from "./types.js";
import { modPow, modInverse, factorial, randomBigInt } from "./keygen.js";

/**
 * Deterministic challenge hash for DLEQ proofs (Fiat-Shamir transform).
 *
 * Uses SHA-256 for collision resistance, which is required for
 * soundness of all Chaum-Pedersen DLEQ proofs.
 */
function dleqChallenge(...values: bigint[]): bigint {
  const input = "DLEQ-V1|" + values.map(v => v.toString(16)).join("|");
  const hash = crypto.createHash("sha256").update(input).digest("hex");
  return BigInt("0x" + hash);
}

/**
 * Create a partial decryption share from a key share.
 *
 * c_i = c^{2 * delta * s_i} mod n²
 *
 * where delta = totalShares!
 *
 * NOTE: We include delta in the exponent here, so that when combining,
 * the Lagrange coefficients are integers (no fractions).
 */
export function createDecryptionShare(
  keyShare: KeyShare,
  ciphertext: bigint,
  totalShares: number
): DecryptionShare {
  const delta = factorial(totalShares);
  const exponent = 2n * delta * keyShare.si;
  const ci = modPow(ciphertext, exponent, keyShare.nSquared);
  return { index: keyShare.index, ci };
}

/**
 * Create a partial decryption share with a DLEQ proof (Chaum-Pedersen).
 *
 * Proves that log_v(v_i) = log_{c^{2*delta}}(c_i) without revealing s_i.
 *
 * @param keyShare    — the secret key share
 * @param ciphertext  — the ciphertext being partially decrypted
 * @param publicKey   — the Paillier public key
 * @param totalShares — total number of shares (l)
 * @param v           — the DLEQ verification generator base
 * @param vi          — the verification key v_i = v^{delta * s_i} mod n²
 * @returns the decryption share and its DLEQ proof
 */
export function createDecryptionShareWithProof(
  keyShare: KeyShare,
  ciphertext: bigint,
  publicKey: PaillierPublicKey,
  totalShares: number,
  v: bigint,
  vi: bigint,
): DecryptionShareWithProof {
  const { nSquared } = publicKey;
  const delta = factorial(totalShares);

  // Compute the decryption share: c_i = c^{2 * delta * s_i} mod n²
  const exponent = 2n * delta * keyShare.si;
  const ci = modPow(ciphertext, exponent, nSquared);

  // DLEQ proof: prove log_v(v_i) = log_{c^{2*delta}}(c_i)
  // Both logs equal delta * s_i.

  // Random nonce r — use n*n bits for statistical hiding
  const rBits = keyShare.n.toString(2).length * 2;
  const r = randomBigInt(rBits);

  // Commitments
  const a = modPow(v, r, nSquared);                          // v^r mod n²
  const b = modPow(ciphertext, 2n * r, nSquared);            // c^{2r} mod n²

  // Challenge (Fiat-Shamir)
  const e = dleqChallenge(v, vi, ciphertext, ci, a, b);

  // Response: z = r + e * delta * s_i  (over the integers, not modular)
  const z = r + e * delta * keyShare.si;

  return {
    share: { index: keyShare.index, ci },
    proof: { a, b, z, e },
  };
}

/**
 * Compute the Lagrange coefficient lambda_{0,j}(0) scaled by delta.
 *
 * lambda_j = delta * product_{k in S, k != j}( (0 - k) / (j - k) )
 *          = delta * product_{k in S, k != j}( k / (k - j) )   [negation cancels]
 *
 * Since we want integer arithmetic, we compute:
 *   numerator   = delta * product_{k != j}( k )
 *   denominator = product_{k != j}( k - j )
 *   result      = numerator / denominator   (exact integer division)
 *
 * Note: indices are small integers (1..l), so this is always exact.
 */
export function lagrangeCoefficient(
  j: number,
  indices: number[],
  delta: bigint
): bigint {
  let num = delta;
  let den = 1n;

  for (const k of indices) {
    if (k === j) continue;
    num *= BigInt(k);
    den *= BigInt(k - j);
  }

  // This division must be exact — verify by checking result * den === num.
  // BigInt division truncates, so we verify the round-trip.
  const result = num / den;
  if (result * den !== num) {
    throw new Error(
      `Non-exact Lagrange division: num=${num}, den=${den}`
    );
  }

  return result;
}

/**
 * Combine decryption shares to recover the plaintext.
 *
 * @param shares      — at least `threshold` decryption shares
 * @param threshold   — minimum number of shares needed
 * @param totalShares — total number of shares (l)
 * @param publicKey   — the Paillier public key
 * @returns the decrypted plaintext as bigint
 */
export function combineDecryptionShares(
  shares: DecryptionShare[],
  threshold: number,
  totalShares: number,
  publicKey: PaillierPublicKey
): bigint {
  if (shares.length < threshold) {
    throw new Error(
      `Need at least ${threshold} shares, got ${shares.length}`
    );
  }

  const { n, nSquared } = publicKey;
  const delta = factorial(totalShares);

  // Use exactly `threshold` shares
  const usedShares = shares.slice(0, threshold);
  const indices = usedShares.map((s) => s.index);

  // Compute cprime = product_i( c_i^{2 * lambda_i} ) mod n²
  let cprime = 1n;
  for (const share of usedShares) {
    const lambda_i = lagrangeCoefficient(share.index, indices, delta);
    const exp = 2n * lambda_i;
    // lambda_i can be negative, modPow handles negative exponents
    cprime = (cprime * modPow(share.ci, exp, nSquared)) % nSquared;
  }

  // L function: L(x) = (x - 1) / n
  const L = (cprime - 1n) / n;

  // Compute (4 * delta²)^{-1} mod n
  const fourDeltaSquared = 4n * delta * delta;
  const inv = modInverse(fourDeltaSquared, n);

  // plaintext = L(cprime) * (4*delta²)^{-1} mod n
  const plaintext = (((L * inv) % n) + n) % n;

  return plaintext;
}

/**
 * Verify a decryption share using its DLEQ proof (Chaum-Pedersen).
 *
 * Verifies the non-interactive proof that:
 *   log_v(v_i) = log_{c^{2*delta}}(c_i)
 *
 * @param share           — the decryption share to verify
 * @param verificationKey — the verification key for this share holder
 * @param ciphertext      — the ciphertext that was partially decrypted
 * @param publicKey       — the Paillier public key
 * @param totalShares     — total number of shares (l)
 * @param v               — the DLEQ verification generator base
 * @param proof           — the DLEQ proof accompanying the share
 * @returns true if the share passes DLEQ verification
 */
export function verifyDecryptionShare(
  share: DecryptionShare,
  verificationKey: VerificationKey,
  ciphertext: bigint,
  publicKey: PaillierPublicKey,
  totalShares: number,
  v: bigint,
  proof: DLEQProof,
): boolean {
  const { nSquared } = publicKey;

  // 1. Index consistency
  if (share.index !== verificationKey.index) {
    return false;
  }

  // 2. Range check: c_i must be in [1, n²) and coprime to n²
  if (share.ci <= 0n || share.ci >= nSquared) {
    return false;
  }

  // 3. The share must not be trivially 1 when ciphertext is not 1
  if (share.ci === 1n && ciphertext !== 1n) {
    return false;
  }

  // 4. GCD check (c_i must be coprime to n²)
  let a = share.ci;
  let b = nSquared;
  while (b > 0n) {
    [a, b] = [b, a % b];
  }
  if (a !== 1n) {
    return false;
  }

  // 5. Full DLEQ cryptographic verification (mandatory)
  const vi = verificationKey.vi;
  const ci = share.ci;

  // Recompute the challenge
  const eCheck = dleqChallenge(v, vi, ciphertext, ci, proof.a, proof.b);
  if (proof.e !== eCheck) {
    return false;
  }

  // Check 1: v^z == a * v_i^e  mod n²
  const lhs1 = modPow(v, proof.z, nSquared);
  const rhs1 = (proof.a * modPow(vi, proof.e, nSquared)) % nSquared;
  if (lhs1 !== rhs1) {
    return false;
  }

  // Check 2: c^{2z} == b * c_i^e  mod n²
  const lhs2 = modPow(ciphertext, 2n * proof.z, nSquared);
  const rhs2 = (proof.b * modPow(ci, proof.e, nSquared)) % nSquared;
  if (lhs2 !== rhs2) {
    return false;
  }

  return true;
}
