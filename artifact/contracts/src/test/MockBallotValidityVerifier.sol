// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract MockBallotValidityVerifier {
    bool public result = true;

    function setResult(bool newResult) external {
        result = newResult;
    }

    function verifyValidity(bytes calldata, bytes calldata) external view returns (bool) {
        return result;
    }
}
