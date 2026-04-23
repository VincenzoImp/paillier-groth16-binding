import { describe, it, expect } from "vitest";

import { generateThresholdKeys } from "./keygen.js";
import { encryptValue } from "./encrypt.js";
import {
  createDecryptionShareWithProof,
  combineDecryptionShares,
  verifyDecryptionShare,
} from "./threshold.js";

describe("DLEQ proof (createDecryptionShareWithProof / verifyDecryptionShare)", () => {
  it("creates and verifies a valid DLEQ proof", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);

    const { share, proof } = createDecryptionShareWithProof(
      keySet.keyShares[0],
      ciphertext,
      pk,
      keySet.totalShares,
      keySet.v,
      keySet.verificationKeys[0].vi,
    );

    const valid = verifyDecryptionShare(
      share,
      keySet.verificationKeys[0],
      ciphertext,
      pk,
      keySet.totalShares,
      keySet.v,
      proof,
    );

    expect(valid).toBe(true);
  });

  it("verifies DLEQ proof for all shares in a keyset", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 99n);

    for (let i = 0; i < keySet.totalShares; i++) {
      const { share, proof } = createDecryptionShareWithProof(
        keySet.keyShares[i],
        ciphertext,
        pk,
        keySet.totalShares,
        keySet.v,
        keySet.verificationKeys[i].vi,
      );

      expect(
        verifyDecryptionShare(
          share,
          keySet.verificationKeys[i],
          ciphertext,
          pk,
          keySet.totalShares,
          keySet.v,
          proof,
        ),
      ).toBe(true);
    }
  });

  it("rejects a DLEQ proof with tampered z value", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 42n);

    const { share, proof } = createDecryptionShareWithProof(
      keySet.keyShares[0],
      ciphertext,
      pk,
      keySet.totalShares,
      keySet.v,
      keySet.verificationKeys[0].vi,
    );

    const tamperedProof = { ...proof, z: proof.z + 1n };

    expect(
      verifyDecryptionShare(
        share,
        keySet.verificationKeys[0],
        ciphertext,
        pk,
        keySet.totalShares,
        keySet.v,
        tamperedProof,
      ),
    ).toBe(false);
  });

  it("rejects a DLEQ proof with tampered e (challenge) value", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 10n);

    const { share, proof } = createDecryptionShareWithProof(
      keySet.keyShares[0],
      ciphertext,
      pk,
      keySet.totalShares,
      keySet.v,
      keySet.verificationKeys[0].vi,
    );

    const tamperedProof = { ...proof, e: proof.e + 1n };

    expect(
      verifyDecryptionShare(
        share,
        keySet.verificationKeys[0],
        ciphertext,
        pk,
        keySet.totalShares,
        keySet.v,
        tamperedProof,
      ),
    ).toBe(false);
  });

  it("rejects a DLEQ proof with tampered share ci", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    const pk = keySet.publicKey;
    const ciphertext = encryptValue(pk, 7n);

    const { share, proof } = createDecryptionShareWithProof(
      keySet.keyShares[0],
      ciphertext,
      pk,
      keySet.totalShares,
      keySet.v,
      keySet.verificationKeys[0].vi,
    );

    const tamperedShare = { ...share, ci: (share.ci + 1n) % pk.nSquared };

    expect(
      verifyDecryptionShare(
        tamperedShare,
        keySet.verificationKeys[0],
        ciphertext,
        pk,
        keySet.totalShares,
        keySet.v,
        proof,
      ),
    ).toBe(false);
  });

  it("shares with DLEQ proofs still decrypt correctly when combined", () => {
    const keySet = generateThresholdKeys(5, 3, 512);
    const pk = keySet.publicKey;
    const plaintext = 42n;
    const ciphertext = encryptValue(pk, plaintext);

    const sharesWithProofs = keySet.keyShares.slice(0, 3).map((ks, i) =>
      createDecryptionShareWithProof(
        ks,
        ciphertext,
        pk,
        keySet.totalShares,
        keySet.v,
        keySet.verificationKeys[i].vi,
      ),
    );

    for (const { share, proof } of sharesWithProofs) {
      const vk = keySet.verificationKeys[share.index - 1];
      expect(
        verifyDecryptionShare(
          share,
          vk,
          ciphertext,
          pk,
          keySet.totalShares,
          keySet.v,
          proof,
        ),
      ).toBe(true);
    }

    const shares = sharesWithProofs.map(sp => sp.share);
    const result = combineDecryptionShares(
      shares,
      keySet.threshold,
      keySet.totalShares,
      pk,
    );
    expect(result).toBe(plaintext);
  });
});
