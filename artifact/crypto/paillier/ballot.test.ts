import { describe, it, expect } from "vitest";
import { generateThresholdKeys } from "./keygen.js";
import { encryptVote } from "./encrypt.js";
import { createDecryptionShare } from "./threshold.js";
import { tallyEncryptedBallots, decryptBallotTally } from "./ballot.js";

describe("tallyEncryptedBallots", () => {
  it("tallies a single ballot (identity)", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    const ballot = encryptVote(pk, { Alice: 5, Bob: 3 });
    const tallied = tallyEncryptedBallots(pk, [ballot]);

    // Decrypt and verify
    const candidates = Array.from(tallied.candidateCiphertexts.keys());
    const shares = candidates.map((c) => {
      const ct = tallied.candidateCiphertexts.get(c)!;
      return keySet.keyShares.slice(0, 2).map((ks) =>
        createDecryptionShare(ks, ct, keySet.totalShares)
      );
    });

    const result = decryptBallotTally(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk,
      tallied,
    );

    expect(result["Alice"]).toBe(5n);
    expect(result["Bob"]).toBe(3n);
  });

  it("throws when given no ballots", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    expect(() => tallyEncryptedBallots(keySet.publicKey, [])).toThrow(
      "At least one ballot required"
    );
  });

  it("throws when ballots have mismatched candidates", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    const b1 = encryptVote(pk, { Alice: 1, Bob: 0 });
    const b2 = encryptVote(pk, { Alice: 1 }); // missing Bob

    expect(() => tallyEncryptedBallots(pk, [b1, b2])).toThrow(
      'Ballot missing candidate "Bob"'
    );
  });
});

describe("decryptBallotTally", () => {
  it("throws when shares array length does not match candidate count", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;
    const ballot = encryptVote(pk, { Alice: 1, Bob: 2 });
    const tallied = tallyEncryptedBallots(pk, [ballot]);

    expect(() =>
      decryptBallotTally([], keySet.threshold, keySet.totalShares, pk, tallied)
    ).toThrow("Expected 2 share arrays");
  });
});

describe("end-to-end: multiple ballots -> tally -> decrypt", () => {
  it("tallies 3 ballots with 2 candidates correctly (3-of-5)", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;

    const b1 = encryptVote(pk, { Alice: 3, Bob: 1 });
    const b2 = encryptVote(pk, { Alice: 2, Bob: 4 });
    const b3 = encryptVote(pk, { Alice: 1, Bob: 2 });

    const tallied = tallyEncryptedBallots(pk, [b1, b2, b3]);

    // Create decryption shares for each candidate's tallied ciphertext
    const candidates = Array.from(tallied.candidateCiphertexts.keys());
    const shares = candidates.map((c) => {
      const ct = tallied.candidateCiphertexts.get(c)!;
      return keySet.keyShares.slice(0, 3).map((ks) =>
        createDecryptionShare(ks, ct, keySet.totalShares)
      );
    });

    const result = decryptBallotTally(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk,
      tallied,
    );

    expect(result["Alice"]).toBe(6n); // 3 + 2 + 1
    expect(result["Bob"]).toBe(7n);   // 1 + 4 + 2
  });

  it("tallies 4 ballots with 3 candidates correctly (2-of-3)", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    const b1 = encryptVote(pk, { Alice: 1, Bob: 0, Charlie: 2 });
    const b2 = encryptVote(pk, { Alice: 0, Bob: 3, Charlie: 1 });
    const b3 = encryptVote(pk, { Alice: 2, Bob: 1, Charlie: 0 });
    const b4 = encryptVote(pk, { Alice: 1, Bob: 1, Charlie: 1 });

    const tallied = tallyEncryptedBallots(pk, [b1, b2, b3, b4]);

    const candidates = Array.from(tallied.candidateCiphertexts.keys());
    const shares = candidates.map((c) => {
      const ct = tallied.candidateCiphertexts.get(c)!;
      return keySet.keyShares.slice(0, 2).map((ks) =>
        createDecryptionShare(ks, ct, keySet.totalShares)
      );
    });

    const result = decryptBallotTally(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk,
      tallied,
    );

    expect(result["Alice"]).toBe(4n);   // 1 + 0 + 2 + 1
    expect(result["Bob"]).toBe(5n);     // 0 + 3 + 1 + 1
    expect(result["Charlie"]).toBe(4n); // 2 + 1 + 0 + 1
  });

  it("tallies zero votes correctly", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    const b1 = encryptVote(pk, { Alice: 0, Bob: 0 });
    const b2 = encryptVote(pk, { Alice: 0, Bob: 0 });

    const tallied = tallyEncryptedBallots(pk, [b1, b2]);

    const candidates = Array.from(tallied.candidateCiphertexts.keys());
    const shares = candidates.map((c) => {
      const ct = tallied.candidateCiphertexts.get(c)!;
      return keySet.keyShares.slice(0, 2).map((ks) =>
        createDecryptionShare(ks, ct, keySet.totalShares)
      );
    });

    const result = decryptBallotTally(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk,
      tallied,
    );

    expect(result["Alice"]).toBe(0n);
    expect(result["Bob"]).toBe(0n);
  });
});
