// @ts-expect-error — circomlibjs has no type declarations
import { buildPoseidon } from "circomlibjs";

export const TREE_DEPTH = 10; // supports up to 1024 leaves

export interface MerkleTree {
  levels: bigint[][];
  depth: number;
}

export interface MerkleProof {
  leaf: bigint;
  pathElements: bigint[];
  pathIndices: number[];
  root: bigint;
}

// Singleton Poseidon instance (lazy-initialised)
let poseidonInstance: Awaited<ReturnType<typeof buildPoseidon>> | null = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Poseidon hash wrapper matching circomlib's Poseidon circuit.
 * Returns the hash as a bigint in the BN254 scalar field.
 */
export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const poseidon = await getPoseidon();
  const hash = poseidon(inputs);
  return BigInt(poseidon.F.toString(hash));
}

/**
 * Build a Merkle tree from a list of leaves.
 * Pads with zeros to 2^TREE_DEPTH and builds bottom-up using Poseidon(left, right).
 */
export async function buildMerkleTree(leaves: bigint[]): Promise<MerkleTree> {
  const numLeaves = 2 ** TREE_DEPTH;
  if (leaves.length > numLeaves) {
    throw new Error(
      `Too many leaves: got ${leaves.length}, max ${numLeaves}`,
    );
  }

  // Pad leaves with zeros
  const paddedLeaves = [...leaves];
  while (paddedLeaves.length < numLeaves) {
    paddedLeaves.push(0n);
  }

  const levels: bigint[][] = [paddedLeaves];

  // Build tree bottom-up
  let currentLevel = paddedLeaves;
  for (let d = 0; d < TREE_DEPTH; d++) {
    const nextLevel: bigint[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const hash = await poseidonHash([currentLevel[i], currentLevel[i + 1]]);
      nextLevel.push(hash);
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return { levels, depth: TREE_DEPTH };
}

/**
 * Returns the Merkle root (top of the tree).
 */
export function getMerkleRoot(tree: MerkleTree): bigint {
  return tree.levels[tree.depth][0];
}

/**
 * Generates a Merkle proof for the leaf at `leafIndex`.
 */
export function getMerkleProof(tree: MerkleTree, leafIndex: number): MerkleProof {
  if (leafIndex < 0 || leafIndex >= 2 ** tree.depth) {
    throw new Error(`Leaf index out of range: ${leafIndex}`);
  }

  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let idx = leafIndex;

  for (let d = 0; d < tree.depth; d++) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    pathElements.push(tree.levels[d][siblingIdx]);
    pathIndices.push(idx % 2); // 0 = left child, 1 = right child
    idx = Math.floor(idx / 2);
  }

  return {
    leaf: tree.levels[0][leafIndex],
    pathElements,
    pathIndices,
    root: getMerkleRoot(tree),
  };
}

/**
 * Compute a leaf commitment: Poseidon(address, secret).
 */
export async function computeLeaf(
  address: bigint,
  secret: bigint,
): Promise<bigint> {
  return poseidonHash([address, secret]);
}

/**
 * Compute a nullifier: Poseidon(secret, nullifierDomain).
 */
export async function computeNullifier(
  secret: bigint,
  nullifierDomain: bigint,
): Promise<bigint> {
  return poseidonHash([secret, nullifierDomain]);
}
