// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IBallotValidityVerifier {
    function verifyValidity(bytes calldata ciphertext, bytes calldata validityProof) external view returns (bool);
}
