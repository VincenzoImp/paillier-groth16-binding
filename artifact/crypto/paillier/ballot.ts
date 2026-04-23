/**
 * Ballot-level helpers for homomorphic tally and threshold decryption.
 *
 * These operate on EncryptedBallot (per-candidate ciphertext maps) and
 * provide a clean API for the full pipeline:
 *   multiple ballots -> tally -> decrypt.
 */

import type {
  PaillierPublicKey,
  EncryptedBallot,
  DecryptionShare,
  DecryptionShareWithProof,
  VerificationKey,
} from "./types.js";
import { homomorphicAdd } from "./encrypt.js";
import { combineDecryptionShares, verifyDecryptionShare } from "./threshold.js";

/**
 * Tally encrypted ballots homomorphically.
 *
 * Given multiple EncryptedBallots, sum the ciphertexts per candidate
 * using the Paillier additive homomorphism: E(a+b) = E(a) * E(b) mod n².
 *
 * All ballots must contain the same set of candidate keys.
 *
 * @param publicKey — the Paillier public key
 * @param ballots   — one or more encrypted ballots to tally
 * @returns a single EncryptedBallot with per-candidate tallied ciphertexts
 */
export function tallyEncryptedBallots(
  publicKey: PaillierPublicKey,
  ballots: EncryptedBallot[],
): EncryptedBallot {
  if (ballots.length === 0) {
    throw new Error("At least one ballot required");
  }

  // Collect all candidate names across all ballots.
  const candidates = new Set<string>();
  for (const ballot of ballots) {
    for (const key of ballot.candidateCiphertexts.keys()) {
      candidates.add(key);
    }
  }

  const tallied = new Map<string, bigint>();

  for (const candidate of candidates) {
    const ciphertexts: bigint[] = [];
    for (const ballot of ballots) {
      const ct = ballot.candidateCiphertexts.get(candidate);
      if (ct === undefined) {
        throw new Error(
          `Ballot missing candidate "${candidate}". All ballots must cover the same candidates.`
        );
      }
      ciphertexts.push(ct);
    }
    tallied.set(candidate, homomorphicAdd(publicKey, ...ciphertexts));
  }

  return { candidateCiphertexts: tallied };
}

/**
 * Decrypt a tallied ballot using threshold decryption.
 *
 * For each candidate, collect partial decryption shares and combine
 * them to recover the plaintext tally.
 *
 * @param shares       — shares[candidateIndex][shareIndex]: decryption shares
 *                       ordered by the candidate iteration order of talliedBallot
 * @param threshold    — minimum number of shares needed
 * @param totalShares  — total number of shares (l)
 * @param publicKey    — the Paillier public key
 * @param talliedBallot — the tallied encrypted ballot to decrypt
 * @returns a mapping from candidate name to decrypted vote count
 */
export function decryptBallotTally(
  shares: DecryptionShare[][],
  threshold: number,
  totalShares: number,
  publicKey: PaillierPublicKey,
  talliedBallot: EncryptedBallot,
): Record<string, bigint> {
  const candidates = Array.from(talliedBallot.candidateCiphertexts.keys());

  if (shares.length !== candidates.length) {
    throw new Error(
      `Expected ${candidates.length} share arrays (one per candidate), got ${shares.length}`
    );
  }

  const result: Record<string, bigint> = {};

  for (let i = 0; i < candidates.length; i++) {
    result[candidates[i]] = combineDecryptionShares(
      shares[i],
      threshold,
      totalShares,
      publicKey,
    );
  }

  return result;
}

/**
 * Decrypt a tallied ballot using threshold decryption with DLEQ share verification.
 *
 * For each candidate, verify all decryption shares using their DLEQ proofs
 * before combining them. This ensures that no party can submit a malicious
 * partial decryption share to corrupt the tally.
 *
 * @param sharesWithProofs — [candidateIdx][shareIdx]: decryption shares with DLEQ proofs
 * @param threshold        — minimum number of shares needed
 * @param totalShares      — total number of shares (l)
 * @param publicKey        — the Paillier public key
 * @param talliedBallot    — the tallied encrypted ballot to decrypt
 * @param v                — the DLEQ verification generator base
 * @param verificationKeys — the verification keys for all share holders
 * @returns a mapping from candidate name to decrypted vote count
 */
export function decryptBallotTallyWithVerification(
  sharesWithProofs: DecryptionShareWithProof[][],
  threshold: number,
  totalShares: number,
  publicKey: PaillierPublicKey,
  talliedBallot: EncryptedBallot,
  v: bigint,
  verificationKeys: VerificationKey[],
): Record<string, bigint> {
  const candidates = Array.from(talliedBallot.candidateCiphertexts.keys());

  if (sharesWithProofs.length !== candidates.length) {
    throw new Error(
      `Expected ${candidates.length} share arrays (one per candidate), got ${sharesWithProofs.length}`
    );
  }

  const result: Record<string, bigint> = {};

  for (let i = 0; i < candidates.length; i++) {
    const candidateShares = sharesWithProofs[i];
    const ciphertext = talliedBallot.candidateCiphertexts.get(candidates[i])!;

    // Verify each share before combining
    for (const { share, proof } of candidateShares) {
      const vk = verificationKeys.find(k => k.index === share.index);
      if (!vk) {
        throw new Error(
          `No verification key found for share index ${share.index}`
        );
      }

      const valid = verifyDecryptionShare(
        share, vk, ciphertext, publicKey, totalShares, v, proof,
      );
      if (!valid) {
        throw new Error(
          `Invalid decryption share for candidate "${candidates[i]}" from share index ${share.index}`
        );
      }
    }

    // All shares verified — combine them
    const shares = candidateShares.map(sp => sp.share);
    result[candidates[i]] = combineDecryptionShares(
      shares,
      threshold,
      totalShares,
      publicKey,
    );
  }

  return result;
}
