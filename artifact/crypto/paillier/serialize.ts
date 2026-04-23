/**
 * Serialization utilities for Paillier threshold encryption types.
 *
 * All bigints are serialized as hex strings (no 0x prefix).
 */

import type {
  PaillierPublicKey,
  SerializedPublicKey,
  KeyShare,
  SerializedKeyShare,
  DecryptionShare,
  SerializedDecryptionShare,
} from "./types.js";

// ─── bigint <-> hex ───────────────────────────────────────────────────

export function bigintToHex(value: bigint): string {
  if (value < 0n) {
    // Store negative values with a leading '-'
    return "-" + (-value).toString(16);
  }
  return value.toString(16);
}

export function hexToBigint(hex: string): bigint {
  if (hex.startsWith("-")) {
    return -BigInt("0x" + hex.slice(1));
  }
  return BigInt("0x" + hex);
}

// ─── Public Key ───────────────────────────────────────────────────────

export function serializePublicKey(pk: PaillierPublicKey): SerializedPublicKey {
  return {
    n: bigintToHex(pk.n),
    g: bigintToHex(pk.g),
  };
}

export function deserializePublicKey(
  spk: SerializedPublicKey
): PaillierPublicKey {
  const n = hexToBigint(spk.n);
  return {
    n,
    g: hexToBigint(spk.g),
    nSquared: n * n,
  };
}

// ─── Key Share ────────────────────────────────────────────────────────

export function serializeKeyShare(ks: KeyShare): SerializedKeyShare {
  return {
    index: ks.index,
    si: bigintToHex(ks.si),
    n: bigintToHex(ks.n),
    nSquared: bigintToHex(ks.nSquared),
  };
}

export function deserializeKeyShare(sks: SerializedKeyShare): KeyShare {
  return {
    index: sks.index,
    si: hexToBigint(sks.si),
    n: hexToBigint(sks.n),
    nSquared: hexToBigint(sks.nSquared),
  };
}

// ─── Decryption Share ─────────────────────────────────────────────────

export function serializeDecryptionShare(
  ds: DecryptionShare
): SerializedDecryptionShare {
  return {
    index: ds.index,
    ci: bigintToHex(ds.ci),
  };
}

export function deserializeDecryptionShare(
  sds: SerializedDecryptionShare
): DecryptionShare {
  return {
    index: sds.index,
    ci: hexToBigint(sds.ci),
  };
}

// ─── Ciphertext ───────────────────────────────────────────────────────

export function serializeCiphertext(c: bigint): string {
  return bigintToHex(c);
}

export function deserializeCiphertext(s: string): bigint {
  return hexToBigint(s);
}
