import { computeVoteHash } from "../crypto/zkp/proof.ts";

async function main() {
  const limbBits = 192;
  const limbBytes = limbBits / 8;
  const limbCount = 32;
  const ciphertextBits = limbBits * limbCount;
  const ciphertextBytes = limbBytes * limbCount;
  const naivePublicInputs = 4;
  const boundPublicInputs = 36;
  const addedPublicInputs = boundPublicInputs - naivePublicInputs;
  const addedCalldataBytes = addedPublicInputs * 32;
  const sampleVoteHash = await computeVoteHash("0x1234567890abcdef");

  console.log(
    JSON.stringify(
      {
        construction: "full-limb cross-group binding",
        ciphertextBits,
        ciphertextBytes,
        limbBits,
        limbBytes,
        limbCount,
        merkleTreeDepth: Math.log2(limbCount),
        naivePublicInputs,
        boundPublicInputs,
        addedPublicInputs,
        addedCalldataBytes,
        sampleVoteHash: `0x${sampleVoteHash.toString(16)}`,
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
