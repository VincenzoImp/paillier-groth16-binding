import { describe, it, expect } from "vitest";
import {
  TREE_DEPTH,
  poseidonHash,
  buildMerkleTree,
  getMerkleRoot,
  getMerkleProof,
  computeLeaf,
  computeNullifier,
} from "./merkle.js";

describe("Poseidon hash", () => {
  it("produces a non-zero bigint", async () => {
    const h = await poseidonHash([1n, 2n]);
    expect(h).toBeTypeOf("bigint");
    expect(h).not.toBe(0n);
  });

  it("is deterministic", async () => {
    const a = await poseidonHash([42n, 99n]);
    const b = await poseidonHash([42n, 99n]);
    expect(a).toBe(b);
  });

  it("different inputs produce different outputs", async () => {
    const a = await poseidonHash([1n, 2n]);
    const b = await poseidonHash([2n, 1n]);
    expect(a).not.toBe(b);
  });
});

describe("Merkle tree", () => {
  it("builds a tree with known leaves and produces a non-zero root", async () => {
    const leaves = [1n, 2n, 3n, 4n];
    const tree = await buildMerkleTree(leaves);
    const root = getMerkleRoot(tree);
    expect(root).not.toBe(0n);
    expect(tree.depth).toBe(TREE_DEPTH);
  });

  it("pads tree correctly with zeros", async () => {
    const leaves = [10n, 20n];
    const tree = await buildMerkleTree(leaves);
    const numLeaves = 2 ** TREE_DEPTH;
    expect(tree.levels[0].length).toBe(numLeaves);
    // First two are our leaves, rest are zeros
    expect(tree.levels[0][0]).toBe(10n);
    expect(tree.levels[0][1]).toBe(20n);
    for (let i = 2; i < numLeaves; i++) {
      expect(tree.levels[0][i]).toBe(0n);
    }
  });

  it("generates proof with pathElements length matching TREE_DEPTH", async () => {
    const leaves = [100n, 200n, 300n];
    const tree = await buildMerkleTree(leaves);
    const proof = getMerkleProof(tree, 1);
    expect(proof.pathElements.length).toBe(TREE_DEPTH);
    expect(proof.pathIndices.length).toBe(TREE_DEPTH);
    expect(proof.leaf).toBe(200n);
    expect(proof.root).toBe(getMerkleRoot(tree));
  });

  it("throws for out-of-range leaf index", async () => {
    const tree = await buildMerkleTree([1n]);
    expect(() => getMerkleProof(tree, -1)).toThrow();
    expect(() => getMerkleProof(tree, 2 ** TREE_DEPTH)).toThrow();
  });

  it("throws when too many leaves are provided", async () => {
    const tooMany = new Array(2 ** TREE_DEPTH + 1).fill(1n);
    await expect(buildMerkleTree(tooMany)).rejects.toThrow("Too many leaves");
  });
});

describe("computeLeaf", () => {
  it("produces consistent results", async () => {
    const a = await computeLeaf(123n, 456n);
    const b = await computeLeaf(123n, 456n);
    expect(a).toBe(b);
  });

  it("different secrets produce different leaves", async () => {
    const a = await computeLeaf(123n, 456n);
    const b = await computeLeaf(123n, 789n);
    expect(a).not.toBe(b);
  });
});

describe("computeNullifier", () => {
  it("produces consistent results", async () => {
    const a = await computeNullifier(456n, 1n);
    const b = await computeNullifier(456n, 1n);
    expect(a).toBe(b);
  });

  it("different nullifier domains produce different nullifiers", async () => {
    const a = await computeNullifier(456n, 1n);
    const b = await computeNullifier(456n, 2n);
    expect(a).not.toBe(b);
  });
});
