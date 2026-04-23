import { readFile } from "node:fs/promises";

import { keccak256, toUtf8Bytes } from "ethers";

function normalizeHex(value) {
  return value.toLowerCase();
}

function canonicalizeTranscript(transcript) {
  return {
    params: {
      ...transcript.params,
      publicKey: normalizeHex(transcript.params.publicKey),
      merkleRoot: normalizeHex(transcript.params.merkleRoot),
    },
    ballots: [...transcript.ballots]
      .map(ballot => ({
        ...ballot,
        ciphertext: normalizeHex(ballot.ciphertext),
        voteHash: normalizeHex(ballot.voteHash),
        validityProofCommitment: normalizeHex(ballot.validityProofCommitment),
      }))
      .sort((a, b) => a.blockNumber - b.blockNumber || a.nullifier.localeCompare(b.nullifier)),
    aggregate: {
      ...transcript.aggregate,
      aggregateCiphertext: normalizeHex(transcript.aggregate.aggregateCiphertext),
      aggregateCommitment: normalizeHex(transcript.aggregate.aggregateCommitment),
    },
    shares: [...transcript.shares]
      .map(share => ({
        ...share,
        share: normalizeHex(share.share),
        shareProofMetadata: normalizeHex(share.shareProofMetadata),
        submitter: share.submitter.toLowerCase(),
      }))
      .sort((a, b) => a.blockNumber - b.blockNumber || a.submitter.localeCompare(b.submitter)),
    result: {
      ...transcript.result,
      resultData: normalizeHex(transcript.result.resultData),
      aggregateCommitment: normalizeHex(transcript.result.aggregateCommitment),
    },
  };
}

async function loadTranscript(path) {
  if (!path) {
    return {
      params: {
        publicKey: "0x1234",
        merkleRoot: "0x" + "11".repeat(32),
        threshold: 2,
        electionIndex: 1,
        nullifierDomain: 123,
        votingDeadlineBlock: 100,
        tallyDeadlineBlock: 120,
      },
      ballots: [
        {
          ciphertext: "0x1234",
          voteHash: "0x" + "99".padStart(64, "0"),
          nullifier: "0x07",
          validityProofCommitment: "0x" + "aa".repeat(32),
          blockNumber: 10,
        },
      ],
      aggregate: {
        aggregateCiphertext: "0xbeef",
        aggregateCommitment: keccak256("0xbeef"),
        ballotCount: 1,
        publishedBlock: 101,
      },
      shares: [
        {
          share: "0x1111",
          shareProofMetadata: keccak256("0xaa"),
          submitter: "0x0000000000000000000000000000000000000001",
          blockNumber: 102,
        },
        {
          share: "0x2222",
          shareProofMetadata: keccak256("0xbb"),
          submitter: "0x0000000000000000000000000000000000000002",
          blockNumber: 103,
        },
      ],
      result: {
        resultData: "0x0102",
        aggregateCommitment: keccak256("0xbeef"),
        sharesCollected: 2,
        finalizedBlock: 104,
      },
    };
  }

  return JSON.parse(await readFile(path, "utf8"));
}

async function main() {
  const transcript = await loadTranscript(process.argv[2]);
  const canonical = canonicalizeTranscript(transcript);
  const digest = keccak256(toUtf8Bytes(JSON.stringify(canonical)));

  console.log(
    JSON.stringify(
      {
        digest,
        ballotCount: canonical.ballots.length,
        shareCount: canonical.shares.length,
        aggregateCommitment: canonical.aggregate.aggregateCommitment,
        canonical,
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
