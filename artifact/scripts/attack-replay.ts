import assert from "node:assert/strict";

import { computeNullifier } from "../crypto/zkp/merkle.ts";
import { computeVoteHash, ciphertextToLimbs } from "../crypto/zkp/proof.ts";

function asHex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

async function main() {
  const root = BigInt("0x" + "11".repeat(32));
  const secret = 77n;
  const nullifierDomain = 1n;
  const nullifier = await computeNullifier(secret, nullifierDomain);

  const victimCiphertext = "0x1234567890abcdef";
  const attackerCiphertext = "0xfedcba0987654321";

  const naiveVictimStatement = {
    root: asHex(root),
    nullifier: asHex(nullifier),
    nullifierDomain: nullifierDomain.toString(),
  };

  const naiveAttackerStatement = {
    root: asHex(root),
    nullifier: asHex(nullifier),
    nullifierDomain: nullifierDomain.toString(),
  };

  const victimVoteHash = await computeVoteHash(victimCiphertext);
  const attackerVoteHash = await computeVoteHash(attackerCiphertext);
  const victimLimbs = ciphertextToLimbs(victimCiphertext);
  const attackerLimbs = ciphertextToLimbs(attackerCiphertext);

  const sameNaiveStatement =
    JSON.stringify(naiveVictimStatement) === JSON.stringify(naiveAttackerStatement);
  const sameBoundStatement =
    victimVoteHash === attackerVoteHash &&
    victimLimbs.every((limb, index) => limb === attackerLimbs[index]);

  assert.equal(sameNaiveStatement, true);
  assert.equal(sameBoundStatement, false);

  console.log(
    JSON.stringify(
      {
        scenario: "ciphertext substitution under proof reuse",
        naiveComposition: {
          reusableStatement: sameNaiveStatement,
          publicStatement: naiveVictimStatement,
          explanation:
            "If ciphertext bytes are not committed by the public statement, an attacker can replay the proof with a substituted ciphertext.",
        },
        boundComposition: {
          reusableStatement: sameBoundStatement,
          victimVoteHash: asHex(victimVoteHash),
          attackerVoteHash: asHex(attackerVoteHash),
          victimFirstLimb: victimLimbs[0],
          attackerFirstLimb: attackerLimbs[0],
          explanation:
            "Cross-group binding exposes the ciphertext-derived statement, so proof reuse no longer matches the posted ballot.",
        },
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
