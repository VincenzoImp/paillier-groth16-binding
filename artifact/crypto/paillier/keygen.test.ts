import { describe, it, expect } from "vitest";
import {
  modPow,
  modInverse,
  extGcd,
  factorial,
  isProbablyPrime,
  generatePrime,
  generateSafePrime,
  generateThresholdKeys,
} from "./keygen.js";

describe("arithmetic helpers", () => {
  it("modPow computes correctly", () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n); // 1024 mod 1000
    expect(modPow(3n, 0n, 7n)).toBe(1n);
    expect(modPow(5n, 1n, 13n)).toBe(5n);
    expect(modPow(2n, 20n, 100n)).toBe(76n); // 1048576 mod 100
  });

  it("modInverse computes correctly", () => {
    expect(modInverse(3n, 7n)).toBe(5n); // 3*5 = 15 ≡ 1 mod 7
    expect(modInverse(7n, 11n)).toBe(8n); // 7*8 = 56 ≡ 1 mod 11
  });

  it("modInverse throws for non-coprime inputs", () => {
    expect(() => modInverse(6n, 9n)).toThrow();
  });

  it("extGcd computes correctly", () => {
    const [g, x, y] = extGcd(35n, 15n);
    expect(g).toBe(5n);
    expect(35n * x + 15n * y).toBe(5n);
  });

  it("factorial computes correctly", () => {
    expect(factorial(0)).toBe(1n);
    expect(factorial(1)).toBe(1n);
    expect(factorial(5)).toBe(120n);
    expect(factorial(10)).toBe(3628800n);
  });
});

describe("primality", () => {
  it("correctly identifies small primes", () => {
    expect(isProbablyPrime(2n)).toBe(true);
    expect(isProbablyPrime(3n)).toBe(true);
    expect(isProbablyPrime(5n)).toBe(true);
    expect(isProbablyPrime(7n)).toBe(true);
    expect(isProbablyPrime(11n)).toBe(true);
    expect(isProbablyPrime(13n)).toBe(true);
  });

  it("correctly identifies small composites", () => {
    expect(isProbablyPrime(0n)).toBe(false);
    expect(isProbablyPrime(1n)).toBe(false);
    expect(isProbablyPrime(4n)).toBe(false);
    expect(isProbablyPrime(9n)).toBe(false);
    expect(isProbablyPrime(15n)).toBe(false);
    expect(isProbablyPrime(100n)).toBe(false);
  });

  it("isProbablyPrime defaults to 64 rounds and still works correctly", () => {
    // Known primes
    expect(isProbablyPrime(104729n)).toBe(true);
    expect(isProbablyPrime(104723n)).toBe(true);
    // Known composites
    expect(isProbablyPrime(104730n)).toBe(false);
    expect(isProbablyPrime(104727n)).toBe(false); // 3 * 34909
    // Generate a prime and verify with explicit 64 rounds
    const p = generatePrime(128);
    expect(isProbablyPrime(p, 64)).toBe(true);
  });

  it("generates a prime of requested bit length", () => {
    const p = generatePrime(64);
    expect(isProbablyPrime(p)).toBe(true);
    // Check bit length is approximately right
    expect(p.toString(2).length).toBe(64);
  });

  it("generates a safe prime", () => {
    const p = generateSafePrime(64);
    expect(isProbablyPrime(p)).toBe(true);
    const pPrime = (p - 1n) / 2n;
    expect(isProbablyPrime(pPrime)).toBe(true);
  });
});

describe("threshold key generation", () => {
  it("generates valid key set with 3-of-5 at 512 bits", () => {
    const keySet = generateThresholdKeys(5, 3, 512);

    expect(keySet.totalShares).toBe(5);
    expect(keySet.threshold).toBe(3);
    expect(keySet.keyShares.length).toBe(5);
    expect(keySet.verificationKeys.length).toBe(5);

    // Public key checks
    const { n, g, nSquared } = keySet.publicKey;
    expect(g).toBe(n + 1n);
    expect(nSquared).toBe(n * n);

    // n should be approximately 512 bits
    const nBits = n.toString(2).length;
    expect(nBits).toBeGreaterThanOrEqual(500);
    expect(nBits).toBeLessThanOrEqual(512);

    // Each share should have correct n and nSquared
    for (const share of keySet.keyShares) {
      expect(share.n).toBe(n);
      expect(share.nSquared).toBe(nSquared);
    }
  });

  it("rejects invalid threshold parameters", () => {
    expect(() => generateThresholdKeys(5, 0, 512)).toThrow();
    expect(() => generateThresholdKeys(5, 1, 512)).toThrow("Threshold must be >= 2");
    expect(() => generateThresholdKeys(5, 6, 512)).toThrow();
  });

  it("includes v (DLEQ generator) in key set", () => {
    const keySet = generateThresholdKeys(3, 2, 512);
    expect(keySet.v).toBeDefined();
    expect(keySet.v > 0n).toBe(true);
    expect(keySet.v < keySet.publicKey.nSquared).toBe(true);
  });
});
