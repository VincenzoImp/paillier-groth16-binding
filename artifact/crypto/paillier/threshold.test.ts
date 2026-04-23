import { describe, it, expect } from "vitest";
import { generateThresholdKeys, factorial } from "./keygen.js";
import { encryptValue, homomorphicAdd, encryptVote } from "./encrypt.js";
import {
  createDecryptionShare,
  createDecryptionShareWithProof,
  combineDecryptionShares,
  lagrangeCoefficient,
  verifyDecryptionShare,
} from "./threshold.js";

describe("threshold decryption", () => {
  it("end-to-end: encrypt 42, decrypt with 3-of-5", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;

    const plaintext = 42n;
    const ciphertext = encryptValue(pk, plaintext);

    // Create decryption shares from first 3 key holders
    const shares = keySet.keyShares.slice(0, 3).map((ks) =>
      createDecryptionShare(ks, ciphertext, keySet.totalShares)
    );

    const result = combineDecryptionShares(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk
    );

    expect(result).toBe(plaintext);
  });

  it("different subset of 3-of-5 shares also decrypts correctly", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;

    const plaintext = 42n;
    const ciphertext = encryptValue(pk, plaintext);

    // Use shares 2, 4, 5 (indices 1, 3, 4 in 0-based)
    const selectedShares = [
      keySet.keyShares[1],
      keySet.keyShares[3],
      keySet.keyShares[4],
    ];

    const shares = selectedShares.map((ks) =>
      createDecryptionShare(ks, ciphertext, keySet.totalShares)
    );

    const result = combineDecryptionShares(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk
    );

    expect(result).toBe(plaintext);
  });

  it("encrypts 0 and decrypts correctly", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    const ciphertext = encryptValue(pk, 0n);
    const shares = keySet.keyShares.slice(0, 2).map((ks) =>
      createDecryptionShare(ks, ciphertext, keySet.totalShares)
    );

    const result = combineDecryptionShares(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk
    );

    expect(result).toBe(0n);
  });

  it("encrypts 1 and decrypts correctly", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    const ciphertext = encryptValue(pk, 1n);
    const shares = keySet.keyShares.slice(0, 2).map((ks) =>
      createDecryptionShare(ks, ciphertext, keySet.totalShares)
    );

    const result = combineDecryptionShares(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk
    );

    expect(result).toBe(1n);
  });

  it("fails with fewer than threshold shares", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;

    const ciphertext = encryptValue(pk, 42n);
    const shares = keySet.keyShares.slice(0, 2).map((ks) =>
      createDecryptionShare(ks, ciphertext, keySet.totalShares)
    );

    expect(() =>
      combineDecryptionShares(
        shares,
        keySet.threshold,
        keySet.totalShares,
        pk
      )
    ).toThrow();
  });
});

describe("verifyDecryptionShare", () => {
  it("returns true for a valid decryption share with DLEQ proof", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);

    const { share, proof } = createDecryptionShareWithProof(
      keySet.keyShares[0], ciphertext, pk, keySet.totalShares,
      keySet.v, keySet.verificationKeys[0].vi,
    );
    const vk = keySet.verificationKeys[0];

    expect(
      verifyDecryptionShare(share, vk, ciphertext, pk, keySet.totalShares, keySet.v, proof)
    ).toBe(true);
  });

  it("returns true for all shares in a keyset with DLEQ proofs", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 100n);

    for (let i = 0; i < keySet.totalShares; i++) {
      const { share, proof } = createDecryptionShareWithProof(
        keySet.keyShares[i], ciphertext, pk, keySet.totalShares,
        keySet.v, keySet.verificationKeys[i].vi,
      );
      const vk = keySet.verificationKeys[i];
      expect(
        verifyDecryptionShare(share, vk, ciphertext, pk, keySet.totalShares, keySet.v, proof)
      ).toBe(true);
    }
  });

  it("returns false when share ci is tampered with", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);

    const { share, proof } = createDecryptionShareWithProof(
      keySet.keyShares[0], ciphertext, pk, keySet.totalShares,
      keySet.v, keySet.verificationKeys[0].vi,
    );
    const vk = keySet.verificationKeys[0];

    // Tamper: set ci to 1 (invalid for non-trivial ciphertext)
    const tamperedShare = { ...share, ci: 1n };
    expect(
      verifyDecryptionShare(tamperedShare, vk, ciphertext, pk, keySet.totalShares, keySet.v, proof)
    ).toBe(false);
  });

  it("returns false when share index does not match verification key", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);

    const { share, proof } = createDecryptionShareWithProof(
      keySet.keyShares[0], ciphertext, pk, keySet.totalShares,
      keySet.v, keySet.verificationKeys[0].vi,
    );
    // Use the wrong verification key
    const wrongVk = keySet.verificationKeys[1];

    expect(
      verifyDecryptionShare(share, wrongVk, ciphertext, pk, keySet.totalShares, keySet.v, proof)
    ).toBe(false);
  });

  it("returns false when share ci is out of range", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);
    const vk = keySet.verificationKeys[0];

    // Need a valid proof for the structural checks (but ci will fail range check first)
    const { proof } = createDecryptionShareWithProof(
      keySet.keyShares[0], ciphertext, pk, keySet.totalShares,
      keySet.v, keySet.verificationKeys[0].vi,
    );

    // ci = 0 (out of range)
    expect(
      verifyDecryptionShare({ index: 1, ci: 0n }, vk, ciphertext, pk, keySet.totalShares, keySet.v, proof)
    ).toBe(false);

    // ci = nSquared (out of range)
    expect(
      verifyDecryptionShare({ index: 1, ci: pk.nSquared }, vk, ciphertext, pk, keySet.totalShares, keySet.v, proof)
    ).toBe(false);
  });

  it("returns false when share ci is not coprime to n²", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);
    const vk = keySet.verificationKeys[0];

    const { proof } = createDecryptionShareWithProof(
      keySet.keyShares[0], ciphertext, pk, keySet.totalShares,
      keySet.v, keySet.verificationKeys[0].vi,
    );

    // ci = n (shares a factor with n²)
    const badShare = { index: 1, ci: pk.n };
    expect(
      verifyDecryptionShare(badShare, vk, ciphertext, pk, keySet.totalShares, keySet.v, proof)
    ).toBe(false);
  });

  it("requires v and proof parameters (no fallback path)", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);

    // Create a share from keyShare[0] but use a proof from keyShare[1]
    // This simulates a share without its own valid proof.
    const share = createDecryptionShare(keySet.keyShares[0], ciphertext, keySet.totalShares);
    const vk = keySet.verificationKeys[0];
    const { proof: wrongProof } = createDecryptionShareWithProof(
      keySet.keyShares[1], ciphertext, pk, keySet.totalShares,
      keySet.v, keySet.verificationKeys[1].vi,
    );

    // Using a mismatched proof must fail — there is no fallback path
    expect(
      verifyDecryptionShare(share, vk, ciphertext, pk, keySet.totalShares, keySet.v, wrongProof)
    ).toBe(false);
  });
});

describe("homomorphic vote tallying (end-to-end)", () => {
  it("tallies votes from 3 universities correctly", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;

    // Three universities submit their votes
    const ballot1 = encryptVote(pk, { Alice: 3, Bob: 1 });
    const ballot2 = encryptVote(pk, { Alice: 2, Bob: 4 });
    const ballot3 = encryptVote(pk, { Alice: 1, Bob: 2 });

    // Homomorphically add per candidate
    const aliceCiphertexts = [
      ballot1.candidateCiphertexts.get("Alice")!,
      ballot2.candidateCiphertexts.get("Alice")!,
      ballot3.candidateCiphertexts.get("Alice")!,
    ];
    const bobCiphertexts = [
      ballot1.candidateCiphertexts.get("Bob")!,
      ballot2.candidateCiphertexts.get("Bob")!,
      ballot3.candidateCiphertexts.get("Bob")!,
    ];

    const aliceTotal = homomorphicAdd(pk, ...aliceCiphertexts);
    const bobTotal = homomorphicAdd(pk, ...bobCiphertexts);

    // Threshold decrypt with 3-of-5 shares
    const aliceShares = keySet.keyShares.slice(0, 3).map((ks) =>
      createDecryptionShare(ks, aliceTotal, keySet.totalShares)
    );
    const bobShares = keySet.keyShares.slice(0, 3).map((ks) =>
      createDecryptionShare(ks, bobTotal, keySet.totalShares)
    );

    const aliceResult = combineDecryptionShares(
      aliceShares,
      keySet.threshold,
      keySet.totalShares,
      pk
    );
    const bobResult = combineDecryptionShares(
      bobShares,
      keySet.threshold,
      keySet.totalShares,
      pk
    );

    expect(aliceResult).toBe(6n); // 3+2+1
    expect(bobResult).toBe(7n); // 1+4+2
  });
});

describe("lagrangeCoefficient", () => {
  it("works with negative-denominator subsets (indices [2, 5, 7])", () => {
    const delta = factorial(7);
    // This subset produces negative denominators for some j values
    const indices = [2, 5, 7];

    // Should not throw for any j in the subset
    for (const j of indices) {
      const coeff = lagrangeCoefficient(j, indices, delta);
      // Verify it is an integer (no throw means exact division succeeded)
      expect(typeof coeff).toBe("bigint");
    }
  });

  it("works with indices [3, 1, 4] which produce negative denominators", () => {
    const delta = factorial(5);
    const indices = [3, 1, 4];

    for (const j of indices) {
      const coeff = lagrangeCoefficient(j, indices, delta);
      expect(typeof coeff).toBe("bigint");
    }
  });

  it("produces correct Lagrange interpolation at 0", () => {
    // For indices [1, 2, 3] with delta=6 (3!):
    // L_1(0) = 6 * (2*3) / ((2-1)*(3-1)) = 6 * 6 / 2 = 18
    // L_2(0) = 6 * (1*3) / ((1-2)*(3-2)) = 6 * 3 / (-1) = -18
    // L_3(0) = 6 * (1*2) / ((1-3)*(2-3)) = 6 * 2 / 2 = 6
    const delta = factorial(3);
    const indices = [1, 2, 3];
    expect(lagrangeCoefficient(1, indices, delta)).toBe(18n);
    expect(lagrangeCoefficient(2, indices, delta)).toBe(-18n);
    expect(lagrangeCoefficient(3, indices, delta)).toBe(6n);
  });
});
