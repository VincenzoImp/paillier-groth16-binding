// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract MockVerifier {
    bool public result = true;

    function setResult(bool newResult) external {
        result = newResult;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[36] calldata
    ) external view returns (bool) {
        return result;
    }
}
