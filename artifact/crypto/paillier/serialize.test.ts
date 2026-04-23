import { describe, it, expect } from "vitest";
import {
  bigintToHex,
  hexToBigint,
  serializePublicKey,
  deserializePublicKey,
  serializeKeyShare,
  deserializeKeyShare,
  serializeDecryptionShare,
  deserializeDecryptionShare,
  serializeCiphertext,
  deserializeCiphertext,
} from "./serialize.js";
import { generateThresholdKeys } from "./keygen.js";
import { encryptValue } from "./encrypt.js";
import { createDecryptionShare } from "./threshold.js";

describe("bigint <-> hex", () => {
  it("round-trips positive bigints", () => {
    const values = [0n, 1n, 42n, 255n, 123456789012345678901234567890n];
    for (const v of values) {
      expect(hexToBigint(bigintToHex(v))).toBe(v);
    }
  });

  it("round-trips negative bigints", () => {
    const v = -42n;
    expect(hexToBigint(bigintToHex(v))).toBe(v);
  });
});

describe("serialization round-trips", () => {
  const keySet = generateThresholdKeys(3, 2, 512);
  const pk = keySet.publicKey;

  it("public key round-trips", () => {
    const serialized = serializePublicKey(pk);
    const deserialized = deserializePublicKey(serialized);
    expect(deserialized.n).toBe(pk.n);
    expect(deserialized.g).toBe(pk.g);
    expect(deserialized.nSquared).toBe(pk.nSquared);
  });

  it("key share round-trips", () => {
    const share = keySet.keyShares[0];
    const serialized = serializeKeyShare(share);
    const deserialized = deserializeKeyShare(serialized);
    expect(deserialized.index).toBe(share.index);
    expect(deserialized.si).toBe(share.si);
    expect(deserialized.n).toBe(share.n);
    expect(deserialized.nSquared).toBe(share.nSquared);
  });

  it("decryption share round-trips", () => {
    const ciphertext = encryptValue(pk, 42n);
    const ds = createDecryptionShare(
      keySet.keyShares[0],
      ciphertext,
      keySet.totalShares
    );
    const serialized = serializeDecryptionShare(ds);
    const deserialized = deserializeDecryptionShare(serialized);
    expect(deserialized.index).toBe(ds.index);
    expect(deserialized.ci).toBe(ds.ci);
  });

  it("ciphertext round-trips", () => {
    const ciphertext = encryptValue(pk, 99n);
    const serialized = serializeCiphertext(ciphertext);
    const deserialized = deserializeCiphertext(serialized);
    expect(deserialized).toBe(ciphertext);
  });

  it("serialized public key is JSON-safe", () => {
    const serialized = serializePublicKey(pk);
    const json = JSON.stringify(serialized);
    const parsed = JSON.parse(json);
    const deserialized = deserializePublicKey(parsed);
    expect(deserialized.n).toBe(pk.n);
  });
});
