/**
 * Paillier Encryption and Homomorphic Operations.
 *
 * Standard Paillier: c = g^m * r^n mod n²
 * With g = n+1: this simplifies to c = (1 + m*n) * r^n mod n²
 *
 * Homomorphic addition: E(a+b) = E(a) * E(b) mod n²
 */

import crypto from "crypto";
import type { PaillierPublicKey, EncryptedBallot, BallotProof, RangeProof, RangeProofK } from "./types.js";
import { modPow, modInverse, randomBigInt } from "./keygen.js";

/**
 * Generate a random r coprime to n, in [1, n-1].
 */
function randomCoprime(n: bigint): bigint {
  const bits = n.toString(2).length;
  while (true) {
    let r = 0n;
    const bytes = Math.ceil(bits / 8);
    const buf = crypto.randomBytes(bytes);
    for (const b of buf) {
      r = (r << 8n) | BigInt(b);
    }
    r = r % n;
    if (r > 0n && gcd(r, n) === 1n) {
      return r;
    }
  }
}

function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b > 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * SHA-256 based Fiat-Shamir challenge for range proofs.
 */
function sha256Challenge(...values: bigint[]): bigint {
  const input = "CDS-OR-V1|" + values.map(v => v.toString(16)).join("|");
  return BigInt("0x" + crypto.createHash("sha256").update(input).digest("hex"));
}

/**
 * Generate a random bigint of exactly `bits` bits using crypto.randomBytes.
 */
function randomBigIntBits(bits: number): bigint {
  const bytes = Math.ceil(bits / 8);
  const buf = crypto.randomBytes(bytes);
  let n = 0n;
  for (const b of buf) {
    n = (n << 8n) | BigInt(b);
  }
  // Mask to exact bit length
  const mask = (1n << BigInt(bits)) - 1n;
  return n & mask;
}

/**
 * Encrypt a plaintext value under the Paillier public key.
 *
 * c = g^m * r^n mod n²
 *
 * @param publicKey — the Paillier public key
 * @param plaintext — the value to encrypt (must be in [0, n))
 * @returns ciphertext as bigint
 */
export function encryptValue(
  publicKey: PaillierPublicKey,
  plaintext: bigint
): bigint {
  const { n, g, nSquared } = publicKey;

  if (plaintext < 0n || plaintext >= n) {
    throw new Error(`plaintext must be in [0, n): got ${plaintext}`);
  }

  const r = randomCoprime(n);

  // c = g^m * r^n mod n²
  const gm = modPow(g, plaintext, nSquared);
  const rn = modPow(r, n, nSquared);
  return (gm * rn) % nSquared;
}

/**
 * Encrypt a plaintext value and also return the randomness r.
 *
 * This is needed for constructing range proofs (CDS OR-proofs),
 * which require knowledge of the randomness used during encryption.
 *
 * @param publicKey — the Paillier public key
 * @param plaintext — the value to encrypt (must be in [0, n))
 * @returns { ciphertext, r } — the ciphertext and the randomness used
 */
export function encryptValueWithRandomness(
  publicKey: PaillierPublicKey,
  plaintext: bigint
): { ciphertext: bigint; r: bigint } {
  const { n, g, nSquared } = publicKey;

  if (plaintext < 0n || plaintext >= n) {
    throw new Error(`plaintext must be in [0, n): got ${plaintext}`);
  }

  const r = randomCoprime(n);

  // c = g^m * r^n mod n²
  const gm = modPow(g, plaintext, nSquared);
  const rn = modPow(r, n, nSquared);
  const ciphertext = (gm * rn) % nSquared;
  return { ciphertext, r };
}

/**
 * Cramer-Damgård-Schoenmakers (CDS) 1-out-of-2 OR-proof.
 *
 * Proves that a Paillier ciphertext c = g^m * r^n mod n² encrypts
 * m ∈ {0, 1} without revealing which value it is.
 *
 * The protocol works by constructing two "shifted" ciphertexts:
 *   c_0 = c          (encrypts m, so if m=0 then c_0 = r^n mod n²)
 *   c_1 = c * g^{-1} (encrypts m-1, so if m=1 then c_1 = r^n mod n²)
 *
 * For the real branch (where the shifted ciphertext is an n-th power),
 * we produce a real Sigma-protocol transcript. For the fake branch,
 * we simulate the transcript. The binding constraint e0 + e1 = H(c, a0, a1)
 * mod 2^256 ensures the prover cannot cheat on both branches.
 *
 * @param publicKey — the Paillier public key
 * @param plaintext — must be 0n or 1n
 * @param r         — the randomness used in encryption
 * @param ciphertext — the ciphertext to prove about
 * @returns a RangeProof (e0, z0, e1, z1)
 */
export function proveVoteRange(
  publicKey: PaillierPublicKey,
  plaintext: bigint,
  r: bigint,
  ciphertext: bigint,
): RangeProof {
  const { n, g, nSquared } = publicKey;
  if (plaintext !== 0n && plaintext !== 1n) {
    throw new Error("Range proof only supports binary votes (0 or 1)");
  }

  const real = Number(plaintext);  // 0 or 1
  const fake = 1 - real;

  // Shifted ciphertexts: c_v = c / g^v mod n²
  // c_0 = c (encrypts m)
  // c_1 = c * g^{-1} mod n² (encrypts m-1)
  const gInv = modInverse(g, nSquared);
  const shiftedCiphertexts = [ciphertext, (ciphertext * gInv) % nSquared];

  // For the real branch (where m-v = 0, so c_v = r^n mod n²):
  // We know the n-th root r.

  // Simulate the fake branch:
  const e_fake = randomBigIntBits(256);
  const z_fake = randomCoprime(n);
  // a_fake = z_fake^n * c_fake^{-e_fake} mod n²
  const a_fake = (modPow(z_fake, n, nSquared) * modPow(modInverse(shiftedCiphertexts[fake], nSquared), e_fake, nSquared)) % nSquared;

  // Real branch commitment:
  const rho = randomCoprime(n);
  const a_real = modPow(rho, n, nSquared); // commitment = rho^n mod n²

  // Order the commitments
  const a: bigint[] = new Array(2);
  a[real] = a_real;
  a[fake] = a_fake;

  // Fiat-Shamir challenge: e = H(c, a_0, a_1)
  const e_total = sha256Challenge(ciphertext, a[0], a[1]);

  // Real challenge: e_real = e_total - e_fake (mod 2^256)
  const MOD = 2n ** 256n;
  const e_real = ((e_total - e_fake) % MOD + MOD) % MOD;

  // Real response: z_real = rho * r^{e_real} mod n
  const z_real = (rho * modPow(r, e_real, n)) % n;

  // Package proof
  const e: bigint[] = new Array(2);
  const z: bigint[] = new Array(2);
  e[real] = e_real;
  e[fake] = e_fake;
  z[real] = z_real;
  z[fake] = z_fake;

  return { e0: e[0], z0: z[0], e1: e[1], z1: z[1] };
}

/**
 * Verify a CDS 1-out-of-2 OR-proof that a ciphertext encrypts 0 or 1.
 *
 * Recomputes the commitments from the proof components and checks
 * that the challenge sum matches the Fiat-Shamir hash.
 *
 * @param publicKey  — the Paillier public key
 * @param ciphertext — the ciphertext to verify
 * @param proof      — the RangeProof to check
 * @returns true if the proof is valid
 */
export function verifyVoteRange(
  publicKey: PaillierPublicKey,
  ciphertext: bigint,
  proof: RangeProof,
): boolean {
  const { n, g, nSquared } = publicKey;
  const gInv = modInverse(g, nSquared);

  // Shifted ciphertexts
  const c0 = ciphertext;
  const c1 = (ciphertext * gInv) % nSquared;

  // Recompute commitments: a_v = z_v^n * c_v^{-e_v} mod n²
  const a0 = (modPow(proof.z0, n, nSquared) * modPow(modInverse(c0, nSquared), proof.e0, nSquared)) % nSquared;
  const a1 = (modPow(proof.z1, n, nSquared) * modPow(modInverse(c1, nSquared), proof.e1, nSquared)) % nSquared;

  // Verify challenge: e0 + e1 = H(c, a0, a1) mod 2^256
  const MOD = 2n ** 256n;
  const e_check = sha256Challenge(ciphertext, a0, a1);
  const e_sum = (proof.e0 + proof.e1) % MOD;

  return e_sum === e_check;
}

/**
 * Cramer-Damgård-Schoenmakers (CDS) 1-out-of-k OR-proof.
 *
 * Proves that a Paillier ciphertext c = g^m * r^n mod n² encrypts
 * m ∈ {0, 1, ..., maxValue} without revealing which value it is.
 *
 * Generalizes the binary CDS proof to k = maxValue + 1 branches.
 * For each candidate value v ∈ {0, ..., maxValue}, we construct:
 *   shifted[v] = c * g^{-v} mod n²
 * If v == plaintext, then shifted[v] = r^n mod n² (an n-th power),
 * and we can produce a real Sigma-protocol transcript.
 * For all other v, we simulate the transcript.
 *
 * The binding constraint: sum(e_v) = H(c, a_0, ..., a_{maxValue}) mod 2^256.
 *
 * @param publicKey  — the Paillier public key
 * @param plaintext  — must be in [0, maxValue]
 * @param r          — the randomness used in encryption
 * @param ciphertext — the ciphertext to prove about
 * @param maxValue   — the maximum allowed value (k-1 where k = number of branches)
 * @returns a RangeProofK
 */
export function proveVoteRangeK(
  publicKey: PaillierPublicKey,
  plaintext: bigint,
  r: bigint,
  ciphertext: bigint,
  maxValue: number,
): RangeProofK {
  const { n, g, nSquared } = publicKey;
  const k = maxValue + 1;

  if (plaintext < 0n || plaintext > BigInt(maxValue)) {
    throw new Error(
      `Range proof: plaintext must be in [0, ${maxValue}], got ${plaintext}`
    );
  }

  const realIndex = Number(plaintext);
  const gInv = modInverse(g, nSquared);

  // Compute shifted ciphertexts: shifted[v] = c * g^{-v} mod n²
  const shifted: bigint[] = new Array(k);
  shifted[0] = ciphertext;
  let gInvPow = 1n;
  for (let v = 1; v < k; v++) {
    gInvPow = (gInvPow * gInv) % nSquared;
    shifted[v] = (ciphertext * gInvPow) % nSquared;
  }

  const MOD = 2n ** 256n;

  // Simulate all fake branches and compute real branch commitment
  const challenges: bigint[] = new Array(k);
  const responses: bigint[] = new Array(k);
  const commitments: bigint[] = new Array(k);

  let fakeChallengeSum = 0n;

  for (let v = 0; v < k; v++) {
    if (v === realIndex) continue;

    // Simulate: pick random e_v, z_v, compute a_v = z_v^n * shifted[v]^{-e_v} mod n²
    challenges[v] = randomBigIntBits(256);
    responses[v] = randomCoprime(n);
    commitments[v] = (
      modPow(responses[v], n, nSquared) *
      modPow(modInverse(shifted[v], nSquared), challenges[v], nSquared)
    ) % nSquared;

    fakeChallengeSum = (fakeChallengeSum + challenges[v]) % MOD;
  }

  // Real branch: pick random rho, commit a_real = rho^n mod n²
  const rho = randomCoprime(n);
  commitments[realIndex] = modPow(rho, n, nSquared);

  // Fiat-Shamir challenge: e_total = H(c, a_0, ..., a_{k-1})
  const eTotal = sha256Challenge(ciphertext, ...commitments);

  // Real challenge: e_real = e_total - sum(fake challenges) mod 2^256
  challenges[realIndex] = ((eTotal - fakeChallengeSum) % MOD + MOD) % MOD;

  // Real response: z_real = rho * r^{e_real} mod n
  responses[realIndex] = (rho * modPow(r, challenges[realIndex], n)) % n;

  return { challenges, responses };
}

/**
 * Verify a CDS 1-out-of-k OR-proof that a ciphertext encrypts a value in {0, ..., maxValue}.
 *
 * Recomputes the commitments from the proof components and checks
 * that the challenge sum matches the Fiat-Shamir hash.
 *
 * @param publicKey  — the Paillier public key
 * @param ciphertext — the ciphertext to verify
 * @param proof      — the RangeProofK to check
 * @param maxValue   — the maximum allowed value (k-1)
 * @returns true if the proof is valid
 */
export function verifyVoteRangeK(
  publicKey: PaillierPublicKey,
  ciphertext: bigint,
  proof: RangeProofK,
  maxValue: number,
): boolean {
  const { n, g, nSquared } = publicKey;
  const k = maxValue + 1;

  if (proof.challenges.length !== k || proof.responses.length !== k) {
    return false;
  }

  const gInv = modInverse(g, nSquared);

  // Compute shifted ciphertexts
  const shifted: bigint[] = new Array(k);
  shifted[0] = ciphertext;
  let gInvPow = 1n;
  for (let v = 1; v < k; v++) {
    gInvPow = (gInvPow * gInv) % nSquared;
    shifted[v] = (ciphertext * gInvPow) % nSquared;
  }

  // Recompute commitments: a_v = z_v^n * shifted[v]^{-e_v} mod n²
  const commitments: bigint[] = new Array(k);
  for (let v = 0; v < k; v++) {
    commitments[v] = (
      modPow(proof.responses[v], n, nSquared) *
      modPow(modInverse(shifted[v], nSquared), proof.challenges[v], nSquared)
    ) % nSquared;
  }

  // Verify: sum(e_v) == H(c, a_0, ..., a_{k-1}) mod 2^256
  const MOD = 2n ** 256n;
  const eCheck = sha256Challenge(ciphertext, ...commitments);
  let eSum = 0n;
  for (const e of proof.challenges) {
    eSum = (eSum + e) % MOD;
  }

  return eSum === eCheck;
}

/**
 * Homomorphically add multiple ciphertexts.
 *
 * E(a + b + ...) = E(a) * E(b) * ... mod n²
 *
 * @param publicKey — the Paillier public key
 * @param ciphertexts — two or more ciphertexts to add
 * @returns combined ciphertext
 */
export function homomorphicAdd(
  publicKey: PaillierPublicKey,
  ...ciphertexts: bigint[]
): bigint {
  if (ciphertexts.length === 0) {
    throw new Error("At least one ciphertext required");
  }

  const { nSquared } = publicKey;
  let result = 1n; // identity for multiplication
  for (const c of ciphertexts) {
    result = (result * c) % nSquared;
  }
  return result;
}

/**
 * Encrypt a vote — a mapping from candidate names to integer counts.
 *
 * @param publicKey — the Paillier public key
 * @param votes — e.g. { "Alice": 1, "Bob": 0 }
 * @returns an EncryptedBallot
 */
export function encryptVote(
  publicKey: PaillierPublicKey,
  votes: Record<string, number>
): EncryptedBallot {
  const candidateCiphertexts = new Map<string, bigint>();
  for (const [candidate, count] of Object.entries(votes)) {
    candidateCiphertexts.set(candidate, encryptValue(publicKey, BigInt(count)));
  }
  return { candidateCiphertexts };
}

/**
 * Encrypt a vote with a CDS OR range proof for each candidate.
 *
 * Each vote value must be in {0, ..., maxVoteWeight}. The range proof
 * cryptographically guarantees the encrypted value is within the allowed
 * range without revealing the actual value.
 *
 * For binary elections (maxVoteWeight=1), uses the original 1-out-of-2 CDS proof.
 * For multi-candidate elections (maxVoteWeight>1), uses the generalized
 * 1-out-of-k CDS proof.
 *
 * @param publicKey     — the Paillier public key
 * @param votes         — mapping from candidate names to vote counts
 * @param maxVoteWeight — maximum allowed vote value per candidate (default 1)
 * @returns encrypted ballot and per-candidate CDS OR range proofs
 */
export function encryptVoteWithProof(
  publicKey: PaillierPublicKey,
  votes: Record<string, number>,
  maxVoteWeight: number = 1,
): { ballot: EncryptedBallot; proofs: Map<string, RangeProofK> } {
  if (maxVoteWeight < 1 || !Number.isInteger(maxVoteWeight)) {
    throw new Error(`maxVoteWeight must be a positive integer, got ${maxVoteWeight}`);
  }

  const candidateCiphertexts = new Map<string, bigint>();
  const proofs = new Map<string, RangeProofK>();

  for (const [candidate, count] of Object.entries(votes)) {
    if (count < 0) {
      throw new Error(`Vote value for "${candidate}" must be non-negative, got ${count}`);
    }
    if (!Number.isInteger(count)) {
      throw new Error(`Vote value for "${candidate}" must be an integer, got ${count}`);
    }
    if (count > maxVoteWeight) {
      throw new Error(
        `Vote value for "${candidate}" exceeds max weight: ${count} > ${maxVoteWeight}`
      );
    }

    const { ciphertext, r } = encryptValueWithRandomness(publicKey, BigInt(count));
    candidateCiphertexts.set(candidate, ciphertext);
    proofs.set(
      candidate,
      proveVoteRangeK(publicKey, BigInt(count), r, ciphertext, maxVoteWeight),
    );
  }

  return {
    ballot: { candidateCiphertexts },
    proofs,
  };
}
