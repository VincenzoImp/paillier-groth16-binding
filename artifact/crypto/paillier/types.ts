/**
 * Type definitions for Shoup's Threshold Paillier Encryption.
 *
 * Based on: "Practical Threshold Signatures" — Victor Shoup (2000)
 * and its application to Paillier as described in
 * "A Generalisation, a Simplification and Some Applications of Paillier's
 * Probabilistic Public-Key System" — Damgård & Jurik (2001).
 */

export interface PaillierPublicKey {
  n: bigint;
  g: bigint;
  nSquared: bigint;
}

export interface KeyShare {
  index: number; // 1-based index
  si: bigint; // secret share value
  n: bigint;
  nSquared: bigint;
}

export interface VerificationKey {
  index: number;
  vi: bigint;
}

export interface ThresholdKeySet {
  publicKey: PaillierPublicKey;
  keyShares: KeyShare[];
  verificationKeys: VerificationKey[];
  threshold: number;
  totalShares: number;
  v: bigint; // generator base for DLEQ verification
}

export interface DecryptionShare {
  index: number;
  ci: bigint;
}

export interface EncryptedBallot {
  candidateCiphertexts: Map<string, bigint>;
}

export interface DLEQProof {
  a: bigint;   // v^r mod n²
  b: bigint;   // c^{2r} mod n²
  z: bigint;   // r + e * delta * s_i
  e: bigint;   // challenge hash
}

export interface DecryptionShareWithProof {
  share: DecryptionShare;
  proof: DLEQProof;
}

export interface RangeProof {
  // 1-out-of-2 OR proof (proving m=0 or m=1)
  e0: bigint;  // simulated challenge for the "other" case
  z0: bigint;  // simulated response
  e1: bigint;  // real or simulated challenge
  z1: bigint;  // real or simulated response
  // e0 + e1 = H(c, a0, a1) — binding constraint
}

export interface RangeProofK {
  // 1-out-of-k OR proof (proving m ∈ {0, 1, ..., maxValue})
  challenges: bigint[];  // e_0, ..., e_{maxValue}
  responses: bigint[];   // z_0, ..., z_{maxValue}
  // sum(challenges[i]) = H(c, a_0, ..., a_{maxValue}) mod 2^256
}

export interface BallotProof {
  // For each candidate: proof that encrypted value is in valid range
  candidateProofs: Map<string, RangeProof>;
}

export interface SerializedPublicKey {
  n: string;
  g: string;
}

export interface SerializedKeyShare {
  index: number;
  si: string;
  n: string;
  nSquared: string;
}

export interface SerializedDecryptionShare {
  index: number;
  ci: string;
}
