// @ts-expect-error — snarkjs has no type declarations
import * as snarkjs from "snarkjs";
import { readFile } from "fs/promises";

/**
 * Verify a Groth16 membership proof client-side.
 *
 * @param proof - The Groth16 proof object from snarkjs
 * @param publicSignals - The public signals array from snarkjs
 * @param vkeyPath - Path to the verification_key.json file
 * @returns true if the proof is valid
 */
export async function verifyMembershipProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: string[],
  vkeyPath: string,
): Promise<boolean> {
  const vkeyJson = await readFile(vkeyPath, "utf-8");
  const vkey = JSON.parse(vkeyJson);
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}
