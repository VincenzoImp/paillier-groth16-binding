/**
 * Shoup's Threshold Paillier Encryption — barrel export.
 */

export type {
  PaillierPublicKey,
  KeyShare,
  VerificationKey,
  ThresholdKeySet,
  DecryptionShare,
  EncryptedBallot,
  DLEQProof,
  DecryptionShareWithProof,
  RangeProof,
  RangeProofK,
  BallotProof,
  SerializedPublicKey,
  SerializedKeyShare,
  SerializedDecryptionShare,
} from "./types.js";

export {
  modPow,
  modInverse,
  extGcd,
  factorial,
  randomBigInt,
  isProbablyPrime,
  generatePrime,
  generateSafePrime,
  generateThresholdKeys,
} from "./keygen.js";

export { encryptValue, encryptValueWithRandomness, homomorphicAdd, encryptVote, encryptVoteWithProof, proveVoteRange, verifyVoteRange, proveVoteRangeK, verifyVoteRangeK } from "./encrypt.js";

export {
  createDecryptionShare,
  createDecryptionShareWithProof,
  combineDecryptionShares,
  lagrangeCoefficient,
  verifyDecryptionShare,
} from "./threshold.js";

export {
  tallyEncryptedBallots,
  decryptBallotTally,
  decryptBallotTallyWithVerification,
} from "./ballot.js";

export {
  bigintToHex,
  hexToBigint,
  serializePublicKey,
  deserializePublicKey,
  serializeKeyShare,
  deserializeKeyShare,
  serializeDecryptionShare,
  deserializeDecryptionShare,
  serializeCiphertext,
  deserializeCiphertext,
} from "./serialize.js";
