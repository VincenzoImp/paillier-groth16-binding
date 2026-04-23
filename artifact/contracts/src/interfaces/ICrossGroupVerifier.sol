// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface ICrossGroupVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[36] calldata publicSignals
    ) external view returns (bool);
}
