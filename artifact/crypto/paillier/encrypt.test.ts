import { describe, it, expect } from "vitest";
import { generateThresholdKeys } from "./keygen.js";
import {
  encryptValue,
  encryptValueWithRandomness,
  homomorphicAdd,
  encryptVote,
  encryptVoteWithProof,
  proveVoteRange,
  verifyVoteRange,
  proveVoteRangeK,
  verifyVoteRangeK,
} from "./encrypt.js";
import { createDecryptionShare, combineDecryptionShares } from "./threshold.js";
import { tallyEncryptedBallots, decryptBallotTally } from "./ballot.js";

describe("encryption", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("encrypts a value and produces valid ciphertext", () => {
    const c = encryptValue(pk, 42n);
    expect(c > 0n).toBe(true);
    expect(c < pk.nSquared).toBe(true);
  });

  it("produces different ciphertexts for same plaintext (randomized)", () => {
    const c1 = encryptValue(pk, 42n);
    const c2 = encryptValue(pk, 42n);
    expect(c1).not.toBe(c2);
  });

  it("rejects negative plaintext", () => {
    expect(() => encryptValue(pk, -1n)).toThrow();
  });

  it("rejects plaintext >= n", () => {
    expect(() => encryptValue(pk, pk.n)).toThrow();
  });
});

describe("encryptValueWithRandomness", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("returns ciphertext and randomness", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 42n);
    expect(ciphertext > 0n).toBe(true);
    expect(ciphertext < pk.nSquared).toBe(true);
    expect(r > 0n).toBe(true);
  });
});

describe("homomorphic addition", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("multiplies ciphertexts mod n²", () => {
    const c1 = encryptValue(pk, 10n);
    const c2 = encryptValue(pk, 20n);
    const cSum = homomorphicAdd(pk, c1, c2);
    expect(cSum > 0n).toBe(true);
    expect(cSum < pk.nSquared).toBe(true);
  });

  it("throws on empty input", () => {
    expect(() => homomorphicAdd(pk)).toThrow();
  });
});

describe("encryptVote", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("encrypts a vote record", () => {
    const ballot = encryptVote(pk, { Alice: 1, Bob: 0 });
    expect(ballot.candidateCiphertexts.size).toBe(2);
    expect(ballot.candidateCiphertexts.has("Alice")).toBe(true);
    expect(ballot.candidateCiphertexts.has("Bob")).toBe(true);
  });
});

describe("CDS OR range proof (proveVoteRange / verifyVoteRange)", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("proves and verifies plaintext = 0", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 0n);
    const proof = proveVoteRange(pk, 0n, r, ciphertext);
    expect(verifyVoteRange(pk, ciphertext, proof)).toBe(true);
  });

  it("proves and verifies plaintext = 1", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 1n);
    const proof = proveVoteRange(pk, 1n, r, ciphertext);
    expect(verifyVoteRange(pk, ciphertext, proof)).toBe(true);
  });

  it("rejects tampered proof (modified e0)", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 1n);
    const proof = proveVoteRange(pk, 1n, r, ciphertext);
    const tampered = { ...proof, e0: proof.e0 + 1n };
    expect(verifyVoteRange(pk, ciphertext, tampered)).toBe(false);
  });

  it("rejects tampered proof (modified z1)", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 0n);
    const proof = proveVoteRange(pk, 0n, r, ciphertext);
    const tampered = { ...proof, z1: proof.z1 + 1n };
    expect(verifyVoteRange(pk, ciphertext, tampered)).toBe(false);
  });

  it("throws for plaintext = 2 (not binary)", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 2n);
    expect(() => proveVoteRange(pk, 2n, r, ciphertext)).toThrow(
      "Range proof only supports binary votes"
    );
  });

  it("rejects proof for wrong ciphertext", () => {
    const { ciphertext: c1, r } = encryptValueWithRandomness(pk, 1n);
    const proof = proveVoteRange(pk, 1n, r, c1);
    const { ciphertext: c2 } = encryptValueWithRandomness(pk, 0n);
    expect(verifyVoteRange(pk, c2, proof)).toBe(false);
  });
});

describe("encryptVoteWithProof", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("encrypts valid vote values (0 and 1) with verifiable range proofs", () => {
    const { ballot, proofs } = encryptVoteWithProof(pk, { Alice: 1, Bob: 0 });
    expect(ballot.candidateCiphertexts.size).toBe(2);
    expect(proofs.size).toBe(2);

    // Verify all range proofs (encryptVoteWithProof now returns RangeProofK)
    for (const [candidate, proof] of proofs.entries()) {
      const ct = ballot.candidateCiphertexts.get(candidate)!;
      expect(verifyVoteRangeK(pk, ct, proof, 1)).toBe(true);
    }
  });

  it("rejects negative vote values", () => {
    expect(() => encryptVoteWithProof(pk, { Alice: -1 })).toThrow("non-negative");
  });

  it("rejects vote values exceeding maxVoteWeight", () => {
    expect(() => encryptVoteWithProof(pk, { Alice: 2 }, 1)).toThrow("exceeds max weight");
  });

  it("accepts maxVoteWeight > 1 with generalized range proof", () => {
    const { ballot, proofs } = encryptVoteWithProof(pk, { Alice: 2 }, 3);
    expect(ballot.candidateCiphertexts.size).toBe(1);
    expect(proofs.size).toBe(1);
    const ct = ballot.candidateCiphertexts.get("Alice")!;
    const proof = proofs.get("Alice")!;
    expect(verifyVoteRangeK(pk, ct, proof, 3)).toBe(true);
  });
});

describe("CDS OR range proof k-out-of-n (proveVoteRangeK / verifyVoteRangeK)", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("proves and verifies each valid value in {0, 1, 2, 3} with maxValue=3", () => {
    for (let v = 0; v <= 3; v++) {
      const { ciphertext, r } = encryptValueWithRandomness(pk, BigInt(v));
      const proof = proveVoteRangeK(pk, BigInt(v), r, ciphertext, 3);
      expect(verifyVoteRangeK(pk, ciphertext, proof, 3)).toBe(true);
    }
  });

  it("throws when plaintext exceeds maxValue", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 4n);
    expect(() => proveVoteRangeK(pk, 4n, r, ciphertext, 3)).toThrow(
      "plaintext must be in [0, 3]"
    );
  });

  it("throws when plaintext is negative", () => {
    expect(() => {
      const { ciphertext, r } = encryptValueWithRandomness(pk, 0n);
      proveVoteRangeK(pk, -1n, r, ciphertext, 3);
    }).toThrow("plaintext must be in [0, 3]");
  });

  it("rejects tampered proof (modified challenge)", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 2n);
    const proof = proveVoteRangeK(pk, 2n, r, ciphertext, 3);
    const tampered = {
      challenges: [...proof.challenges],
      responses: [...proof.responses],
    };
    tampered.challenges[0] = tampered.challenges[0] + 1n;
    expect(verifyVoteRangeK(pk, ciphertext, tampered, 3)).toBe(false);
  });

  it("rejects tampered proof (modified response)", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 1n);
    const proof = proveVoteRangeK(pk, 1n, r, ciphertext, 3);
    const tampered = {
      challenges: [...proof.challenges],
      responses: [...proof.responses],
    };
    tampered.responses[2] = tampered.responses[2] + 1n;
    expect(verifyVoteRangeK(pk, ciphertext, tampered, 3)).toBe(false);
  });

  it("rejects proof for wrong ciphertext", () => {
    const { ciphertext: c1, r } = encryptValueWithRandomness(pk, 2n);
    const proof = proveVoteRangeK(pk, 2n, r, c1, 3);
    const { ciphertext: c2 } = encryptValueWithRandomness(pk, 1n);
    expect(verifyVoteRangeK(pk, c2, proof, 3)).toBe(false);
  });

  it("rejects proof with wrong maxValue", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 1n);
    const proof = proveVoteRangeK(pk, 1n, r, ciphertext, 3);
    // Verify with maxValue=2 should fail (wrong k)
    expect(verifyVoteRangeK(pk, ciphertext, proof, 2)).toBe(false);
  });

  it("works for maxValue=1 (binary, equivalent to original proof)", () => {
    const { ciphertext, r } = encryptValueWithRandomness(pk, 0n);
    const proof = proveVoteRangeK(pk, 0n, r, ciphertext, 1);
    expect(verifyVoteRangeK(pk, ciphertext, proof, 1)).toBe(true);

    const { ciphertext: c2, r: r2 } = encryptValueWithRandomness(pk, 1n);
    const proof2 = proveVoteRangeK(pk, 1n, r2, c2, 1);
    expect(verifyVoteRangeK(pk, c2, proof2, 1)).toBe(true);
  });
});

describe("encryptVoteWithProof with maxVoteWeight > 1", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("encrypts vote with maxVoteWeight=3 and produces valid proofs", () => {
    const { ballot, proofs } = encryptVoteWithProof(
      pk,
      { Alice: 3, Bob: 0, Charlie: 1 },
      3,
    );
    expect(ballot.candidateCiphertexts.size).toBe(3);
    expect(proofs.size).toBe(3);

    for (const [candidate, proof] of proofs.entries()) {
      const ct = ballot.candidateCiphertexts.get(candidate)!;
      expect(verifyVoteRangeK(pk, ct, proof, 3)).toBe(true);
    }
  });

  it("rejects vote exceeding maxVoteWeight", () => {
    expect(() =>
      encryptVoteWithProof(pk, { Alice: 4 }, 3)
    ).toThrow("exceeds max weight");
  });

  it("rejects negative maxVoteWeight", () => {
    expect(() =>
      encryptVoteWithProof(pk, { Alice: 0 }, -1)
    ).toThrow("maxVoteWeight must be a positive integer");
  });
});

describe("full pipeline: encrypt with proof -> verify -> tally -> decrypt", () => {
  it("encrypts binary votes with proofs, tallies, and decrypts correctly", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    // Three voters each vote for one of two candidates
    const { ballot: b1, proofs: p1 } = encryptVoteWithProof(pk, { Alice: 1, Bob: 0 });
    const { ballot: b2, proofs: p2 } = encryptVoteWithProof(pk, { Alice: 0, Bob: 1 });
    const { ballot: b3, proofs: p3 } = encryptVoteWithProof(pk, { Alice: 1, Bob: 1 });

    // Verify all range proofs (now returns RangeProofK)
    for (const [ballotData, proofs] of [[b1, p1], [b2, p2], [b3, p3]] as [typeof b1, typeof p1][]) {
      for (const [candidate, proof] of proofs.entries()) {
        const ct = ballotData.candidateCiphertexts.get(candidate)!;
        expect(verifyVoteRangeK(pk, ct, proof, 1)).toBe(true);
      }
    }

    // Tally
    const tallied = tallyEncryptedBallots(pk, [b1, b2, b3]);

    // Decrypt
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

    expect(result["Alice"]).toBe(2n); // 1 + 0 + 1
    expect(result["Bob"]).toBe(2n);   // 0 + 1 + 1
  });
});

describe("full pipeline: 3 candidates, 5 voters, multi-candidate election", () => {
  it("encrypts weighted votes, verifies proofs, tallies, and decrypts correctly", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;

    // 5 voters in a 3-candidate election, each can assign 0-3 points per candidate
    const maxWeight = 3;
    const voterChoices = [
      { Alice: 3, Bob: 0, Charlie: 1 },
      { Alice: 0, Bob: 2, Charlie: 3 },
      { Alice: 1, Bob: 1, Charlie: 1 },
      { Alice: 2, Bob: 3, Charlie: 0 },
      { Alice: 0, Bob: 0, Charlie: 2 },
    ];

    const ballots: ReturnType<typeof encryptVoteWithProof>[] = [];
    for (const votes of voterChoices) {
      const result = encryptVoteWithProof(pk, votes, maxWeight);
      ballots.push(result);
    }

    // Verify all range proofs
    for (const { ballot, proofs } of ballots) {
      for (const [candidate, proof] of proofs.entries()) {
        const ct = ballot.candidateCiphertexts.get(candidate)!;
        expect(verifyVoteRangeK(pk, ct, proof, maxWeight)).toBe(true);
      }
    }

    // Tally
    const tallied = tallyEncryptedBallots(
      pk,
      ballots.map((b) => b.ballot),
    );

    // Decrypt
    const candidates = Array.from(tallied.candidateCiphertexts.keys());
    const decShares = candidates.map((c) => {
      const ct = tallied.candidateCiphertexts.get(c)!;
      return keySet.keyShares.slice(0, 2).map((ks) =>
        createDecryptionShare(ks, ct, keySet.totalShares)
      );
    });

    const result = decryptBallotTally(
      decShares,
      keySet.threshold,
      keySet.totalShares,
      pk,
      tallied,
    );

    // Expected: Alice: 3+0+1+2+0=6, Bob: 0+2+1+3+0=6, Charlie: 1+3+1+0+2=7
    expect(result["Alice"]).toBe(6n);
    expect(result["Bob"]).toBe(6n);
    expect(result["Charlie"]).toBe(7n);
  });
});
