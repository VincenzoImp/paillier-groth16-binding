/**
 * Threshold Paillier Key Generation — Shoup's Construction.
 *
 * Generates safe primes p = 2p'+1, q = 2q'+1, computes n = p*q,
 * and produces a set of Shamir secret shares of a specially constructed
 * secret d such that d ≡ 0 (mod m) and d ≡ 1 (mod n), where m = p'*q'.
 *
 * The shares are evaluated over Z_{n*m} so that partial decryption
 * and Lagrange recombination work correctly in Shoup's protocol.
 */

import crypto from "crypto";
import type {
  PaillierPublicKey,
  KeyShare,
  VerificationKey,
  ThresholdKeySet,
} from "./types.js";

// ─── Arithmetic helpers ───────────────────────────────────────────────

/** Modular exponentiation: base^exp mod mod. Handles negative exponents via modInverse. */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  if (exp < 0n) {
    return modPow(modInverse(base, mod), -exp, mod);
  }
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod;
    }
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/** Extended GCD: returns [gcd, x, y] such that a*x + b*y = gcd. */
export function extGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (a === 0n) return [b, 0n, 1n];
  const [g, x1, y1] = extGcd(((b % a) + a) % a, a);
  return [g, y1 - (b / a) * x1, x1];
}

/** Modular inverse of a mod m. Throws if gcd(a, m) !== 1. */
export function modInverse(a: bigint, m: bigint): bigint {
  a = ((a % m) + m) % m;
  const [g, x] = extGcd(a, m);
  if (g !== 1n) {
    throw new Error(`modInverse: no inverse exists (gcd=${g})`);
  }
  return ((x % m) + m) % m;
}

/** Factorial of n (bigint). */
export function factorial(n: number): bigint {
  let result = 1n;
  for (let i = 2; i <= n; i++) {
    result *= BigInt(i);
  }
  return result;
}

// ─── Random / Primality ───────────────────────────────────────────────

/** Generate a cryptographically random bigint of exactly `bits` bits. */
export function randomBigInt(bits: number): bigint {
  const bytes = Math.ceil(bits / 8);
  const buf = crypto.randomBytes(bytes);
  let n = 0n;
  for (const b of buf) {
    n = (n << 8n) | BigInt(b);
  }
  // Mask to exact bit length and set the top bit
  const mask = (1n << BigInt(bits)) - 1n;
  n = n & mask;
  n = n | (1n << BigInt(bits - 1)); // ensure exactly `bits` bits
  return n;
}

/** Generate a random bigint in [2, max-2]. */
function randomInRange(max: bigint): bigint {
  const bits = max.toString(2).length;
  let r: bigint;
  do {
    r = randomBigInt(bits) % max;
  } while (r < 2n);
  return r;
}

/**
 * Miller-Rabin primality test.
 * @param n — candidate
 * @param rounds — number of witnesses (default 20)
 */
export function isProbablyPrime(n: bigint, rounds = 64): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  // Write n-1 as 2^r * d
  let r = 0n;
  let d = n - 1n;
  while (d % 2n === 0n) {
    d >>= 1n;
    r++;
  }

  for (let i = 0; i < rounds; i++) {
    const a = randomInRange(n - 2n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;

    let composite = true;
    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

/** Generate a random probable prime of `bits` bits. */
export function generatePrime(bits: number): bigint {
  if (typeof crypto.generatePrimeSync === "function") {
    while (true) {
      const candidate = crypto.generatePrimeSync(bits, { bigint: true });
      if (candidate.toString(2).length === bits) {
        return candidate;
      }
    }
  }

  while (true) {
    let candidate = randomBigInt(bits);
    // Make sure it's odd
    candidate |= 1n;
    if (isProbablyPrime(candidate, 64)) {
      return candidate;
    }
  }
}

/**
 * Generate a safe prime p = 2p' + 1 of `bits` bits,
 * where both p' and p are (probable) primes.
 */
export function generateSafePrime(bits: number): bigint {
  if (typeof crypto.generatePrimeSync === "function") {
    while (true) {
      const candidate = crypto.generatePrimeSync(bits, { bigint: true, safe: true });
      if (candidate.toString(2).length === bits) {
        return candidate;
      }
    }
  }

  while (true) {
    // Generate p' of (bits-1) bits, then p = 2p'+1 has `bits` bits
    const pPrime = generatePrime(bits - 1);
    const p = 2n * pPrime + 1n;
    if (isProbablyPrime(p, 64)) {
      return p;
    }
  }
}

// ─── Threshold Key Generation ─────────────────────────────────────────

/**
 * Generate a full threshold key set using Shoup's construction.
 *
 * @param totalShares — total number of key shares (l)
 * @param threshold   — minimum shares needed to decrypt (t+1 in Shoup, we use threshold)
 * @param keyBits     — bit size of n (each prime is keyBits/2 bits). Default 3072.
 */
export function generateThresholdKeys(
  totalShares: number,
  threshold: number,
  keyBits = 3072
): ThresholdKeySet {
  if (threshold < 2) {
    throw new Error("Threshold must be >= 2 for meaningful security");
  }
  if (threshold > totalShares) {
    throw new Error("threshold must be in [2, totalShares]");
  }

  // 1. Generate safe primes
  const halfBits = Math.floor(keyBits / 2);
  const p = generateSafePrime(halfBits);
  const q = generateSafePrime(halfBits);

  const n = p * q;
  const nSquared = n * n;

  // Sophie Germain primes
  const pPrime = (p - 1n) / 2n;
  const qPrime = (q - 1n) / 2n;
  const m = pPrime * qPrime; // This is the secret order, NOT lambda

  // 2. Public key: g = n + 1 (standard simplification)
  const g = n + 1n;

  const publicKey: PaillierPublicKey = { n, g, nSquared };

  // 3. Compute secret d such that d ≡ 0 (mod m) AND d ≡ 1 (mod n)
  //    Using CRT: d = m * (m^{-1} mod n)
  const mInvModN = modInverse(m, n);
  const d = (m * mInvModN) % (n * m); // d mod m = 0, d mod n = m * m^{-1} mod n = 1

  // 4. Shamir secret sharing of d over Z_{n*m}
  //    Polynomial: f(x) = d + a_1*x + ... + a_{t-1}*x^{t-1}  (degree threshold-1)
  const nm = n * m;

  // Random polynomial coefficients
  const coefficients: bigint[] = [d];
  for (let i = 1; i < threshold; i++) {
    // Random coefficient in [0, n*m)
    const bits = nm.toString(2).length;
    let coeff: bigint;
    do {
      coeff = randomBigInt(bits);
    } while (coeff >= nm);
    coefficients.push(coeff);
  }

  // Evaluate polynomial at points 1..totalShares
  const keyShares: KeyShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    let si = 0n;
    const x = BigInt(i);
    let xPow = 1n;
    for (let j = 0; j < coefficients.length; j++) {
      si += coefficients[j] * xPow;
      xPow *= x;
    }
    // Reduce mod n*m to keep shares manageable
    // (Not strictly required but good practice)
    si = ((si % nm) + nm) % nm;

    keyShares.push({ index: i, si, n, nSquared });
  }

  // 5. Verification keys: v = random generator of QR_n², v_i = v^{delta * s_i} mod n²
  const delta = factorial(totalShares);

  // Pick v as a random square mod n² (guaranteed to be in QR_n²)
  let vBase: bigint;
  do {
    vBase = randomBigInt(keyBits);
    vBase = ((vBase % nSquared) + nSquared) % nSquared;
  } while (vBase === 0n);
  const v = modPow(vBase, 2n, nSquared); // squaring ensures it's a QR

  const verificationKeys: VerificationKey[] = [];
  for (const share of keyShares) {
    const vi = modPow(v, delta * share.si, nSquared);
    verificationKeys.push({ index: share.index, vi });
  }

  return {
    publicKey,
    keyShares,
    verificationKeys,
    threshold,
    totalShares,
    v,
  };
}
