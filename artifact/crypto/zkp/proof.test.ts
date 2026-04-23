import { describe, it, expect } from "vitest";
import { existsSync } from "fs";
import { fileURLToPath } from "url";
import {
  buildMerkleTree,
  getMerkleProof,
  computeLeaf,
  computeNullifier,
} from "./merkle.js";
import { generateMembershipProof, formatProofForSolidity, computeVoteHash } from "./proof.js";
import { verifyMembershipProof } from "./verify.js";

const BASE_URL = new URL("../../circuits/build/", import.meta.url);
const WASM_PATH = fileURLToPath(new URL("CrossGroupBallot_js/CrossGroupBallot.wasm", BASE_URL));
const ZKEY_PATH = fileURLToPath(new URL("circuit_final.zkey", BASE_URL));
const VKEY_PATH = fileURLToPath(new URL("verification_key.json", BASE_URL));

const ARTIFACTS_EXIST = existsSync(WASM_PATH) && existsSync(ZKEY_PATH) && existsSync(VKEY_PATH);

describe.skipIf(!ARTIFACTS_EXIST)("ZKP Proof Generation", () => {
  it("generates and verifies a membership proof end-to-end", async () => {
    // 1. Create a leaf commitment
    const secret = 12345n;
    const address = 0xABCDEF0123456789n;
    const nullifierDomain = 42n;
    const ciphertextHex = "0xdeadbeefcafebabe0123456789abcdef"; // test ciphertext

    const leaf = await computeLeaf(address, secret);
    expect(leaf).not.toBe(0n);

    // 2. Build a Merkle tree with that leaf
    const tree = await buildMerkleTree([leaf]);

    // 3. Get the Merkle proof
    const merkleProof = getMerkleProof(tree, 0);

    // 4. Generate a membership proof
    const { proof, publicSignals } = await generateMembershipProof(
      { secret, address, nullifierDomain, ciphertextHex },
      merkleProof,
      { wasmPath: WASM_PATH, zkeyPath: ZKEY_PATH },
    );

    expect(proof).toBeDefined();
    expect(publicSignals).toBeDefined();
    expect(publicSignals).toHaveLength(36); // root, nullifier, nullifierDomain, voteHash, ctLimbs[32]

    // 5. Verify the proof client-side
    const valid = await verifyMembershipProof(proof, publicSignals, VKEY_PATH);
    expect(valid).toBe(true);

    // 6. publicSignals[0] matches the tree root
    expect(BigInt(publicSignals[0])).toBe(merkleProof.root);

    // 7. publicSignals[1] matches the expected nullifier
    const expectedNullifier = await computeNullifier(secret, nullifierDomain);
    expect(BigInt(publicSignals[1])).toBe(expectedNullifier);

    // 8. publicSignals[3] matches the Poseidon hash of ciphertext limbs
    const expectedVoteHash = await computeVoteHash(ciphertextHex);
    expect(BigInt(publicSignals[3])).toBe(expectedVoteHash);

    // 9. publicSignals[4..35] are the exposed ciphertext limbs
    expect(BigInt(publicSignals[4])).toBeGreaterThanOrEqual(0n);
  }, 120_000);

  it("formats proof for Solidity correctly", async () => {
    const secret = 99999n;
    const address = 0x1234n;
    const nullifierDomain = 1n;
    const ciphertextHex = "0xabcdef0123456789";

    const leaf = await computeLeaf(address, secret);
    const tree = await buildMerkleTree([leaf]);
    const merkleProof = getMerkleProof(tree, 0);

    const { proof } = await generateMembershipProof(
      { secret, address, nullifierDomain, ciphertextHex },
      merkleProof,
      { wasmPath: WASM_PATH, zkeyPath: ZKEY_PATH },
    );

    const solProof = formatProofForSolidity(proof);
    expect(solProof.pA).toHaveLength(2);
    expect(solProof.pB).toHaveLength(2);
    expect(solProof.pB[0]).toHaveLength(2);
    expect(solProof.pB[1]).toHaveLength(2);
    expect(solProof.pC).toHaveLength(2);
  }, 120_000);
});
