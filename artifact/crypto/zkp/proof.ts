// @ts-expect-error — snarkjs has no type declarations
import * as snarkjs from "snarkjs";
import { computeNullifier, poseidonHash, type MerkleProof } from "./merkle.js";

export interface ProofInput {
  secret: bigint;
  address: bigint;
  nullifierDomain: bigint;
  ciphertextHex: string; // hex-encoded Paillier ciphertext (all 6144 bits hashed in-circuit)
}

export interface CircuitPaths {
  wasmPath: string;
  zkeyPath: string;
}

export interface GeneratedProof {
  proof: snarkjs.Groth16Proof;
  publicSignals: string[];
}

export interface BoundBallotPackage {
  ciphertextHex: string;
  voteHash: bigint;
  publicSignals: bigint[];
  proof: snarkjs.Groth16Proof;
}

export interface SolidityProof {
  pA: [string, string];
  pB: [[string, string], [string, string]];
  pC: [string, string];
}

/**
 * Split a ciphertext hex string into 32 limbs for the circuit's Poseidon
 * Merkle tree binding.
 *
 * A 3072-bit Paillier modulus yields ciphertexts in Z_{n^2} (6144 bits).
 * We use a fixed-radix base-2^192 decomposition: 6144 / 192 = 32 limbs
 * exactly. Each 192-bit limb (24 bytes = 48 hex chars) fits within the
 * BN254 scalar field (p ≈ 2^254) without reduction, preserving injectivity
 * of the decomposition --- which is critical for binding security.
 */
/**
 * Canonical ciphertext width in bytes. The contract enforces this exactly;
 * the proof helpers must agree.
 */
export const CANONICAL_CIPHERTEXT_BYTES = 768;
export function ciphertextToLimbs(ciphertextHex: string, numLimbs: number = 32): string[] {
  const hex = ciphertextHex.startsWith("0x") ? ciphertextHex.slice(2) : ciphertextHex;
  const LIMB_BITS = 192;
  const LIMB_HEX = LIMB_BITS / 4; // 48 hex chars per limb
  const totalHex = numLimbs * LIMB_HEX; // 1536 hex chars = 6144 bits

  // Reject non-canonical width: the contract requires exactly 768 bytes,
  // and the binding theorem depends on injective decomposition of a
  // fixed-width representation. Silently padding/truncating here would
  // break the security assumption.
  if (hex.length > totalHex) {
    throw new Error(
      `Ciphertext too large for canonical decomposition: ${hex.length / 2} bytes > ${totalHex / 2} bytes`
    );
  }

  const padded = hex.padStart(totalHex, "0");

  const limbs: string[] = [];
  for (let i = 0; i < numLimbs; i++) {
    const chunk = padded.slice(i * LIMB_HEX, (i + 1) * LIMB_HEX);
    limbs.push(BigInt("0x" + chunk).toString());
  }
  return limbs;
}

/**
 * Compute the voteHash by building a binary Poseidon Merkle tree over all
 * 32 ciphertext limbs (matching the circuit).
 */
export async function computeVoteHash(ciphertextHex: string): Promise<bigint> {
  const limbs = ciphertextToLimbs(ciphertextHex);
  let level = limbs.map((l) => BigInt(l));
  while (level.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(await poseidonHash([level[i], level[i + 1]]));
    }
    level = next;
  }
  return level[0];
}

/**
 * Generate a Groth16 membership proof.
 *
 * The circuit expects:
 *   Private inputs: secret, address, pathElements[], pathIndices[]
 *   Public inputs:  root, nullifier, nullifierDomain, voteHash, ctLimbs[32]
 */
export async function generateMembershipProof(
  input: ProofInput,
  merkleProof: MerkleProof,
  paths: CircuitPaths,
): Promise<GeneratedProof> {
  const nullifier = await computeNullifier(input.secret, input.nullifierDomain);
  const ctLimbs = ciphertextToLimbs(input.ciphertextHex);
  const voteHash = await computeVoteHash(input.ciphertextHex);

  const circuitInput = {
    secret: input.secret.toString(),
    address: input.address.toString(),
    pathElements: merkleProof.pathElements.map((e) => e.toString()),
    pathIndices: merkleProof.pathIndices,
    root: merkleProof.root.toString(),
    nullifier: nullifier.toString(),
    nullifierDomain: input.nullifierDomain.toString(),
    voteHash: voteHash.toString(),
    ctLimbs,
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    paths.wasmPath,
    paths.zkeyPath,
  );

  return { proof, publicSignals };
}

export function publicSignalsToBigInts(publicSignals: string[]): bigint[] {
  return publicSignals.map((value) => BigInt(value));
}

export async function buildBoundBallotPackage(
  input: ProofInput,
  merkleProof: MerkleProof,
  paths: CircuitPaths,
): Promise<BoundBallotPackage> {
  const { proof, publicSignals } = await generateMembershipProof(input, merkleProof, paths);
  return {
    ciphertextHex: input.ciphertextHex,
    voteHash: BigInt(publicSignals[3]),
    publicSignals: publicSignalsToBigInts(publicSignals),
    proof,
  };
}

/**
 * Format a snarkjs proof for the Solidity verifier.
 * NOTE: pB coordinates are reversed per snarkjs/Solidity convention.
 */
export function formatProofForSolidity(proof: snarkjs.Groth16Proof): SolidityProof {
  return {
    pA: [proof.pi_a[0], proof.pi_a[1]],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]], // reversed
      [proof.pi_b[1][1], proof.pi_b[1][0]], // reversed
    ],
    pC: [proof.pi_c[0], proof.pi_c[1]],
  };
}
