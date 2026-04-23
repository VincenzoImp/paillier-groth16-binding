// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ICrossGroupVerifier} from "../interfaces/ICrossGroupVerifier.sol";

/// @title NaiveBallotBox
/// @notice Deliberately INSECURE contract that omits cross-group binding checks.
/// @dev Used ONLY to demonstrate the ciphertext-substitution attack in tests.
///      The proof is verified but the contract does NOT check that the posted
///      ciphertext bytes match the public limb inputs in the proof statement.
contract NaiveBallotBox {
    ICrossGroupVerifier public immutable verifier;
    address public owner;

    uint256 public electionId;
    bytes32 public merkleRoot;
    bool public voting;

    mapping(uint256 => mapping(uint256 => bool)) internal _spentNullifiers;

    struct NaiveBallot {
        bytes ciphertext;
        uint256 nullifier;
    }

    NaiveBallot[] public ballots;

    event NaiveBallotAccepted(uint256 indexed electionId, uint256 nullifier);

    error NullifierAlreadySpent();
    error InvalidProof();
    error NotVoting();
    error InvalidRoot();

    constructor(address verifierAddr) {
        verifier = ICrossGroupVerifier(verifierAddr);
        owner = msg.sender;
    }

    function startElection(uint256 eid, bytes32 root) external {
        electionId = eid;
        merkleRoot = root;
        voting = true;
    }

    /// @notice INSECURE: accepts any ciphertext bytes without checking against public inputs.
    function castBallot(
        bytes calldata ciphertext,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[36] calldata publicInputs
    ) external {
        if (!voting) revert NotVoting();
        if (publicInputs[0] != uint256(merkleRoot)) revert InvalidRoot();

        uint256 nullifier = publicInputs[1];
        if (_spentNullifiers[electionId][nullifier]) revert NullifierAlreadySpent();

        // NOTE: NO ciphertext-to-limb binding check here!
        // This is the vulnerability: the contract trusts the proof but never
        // verifies that the posted ciphertext matches the limbs in the statement.

        if (!verifier.verifyProof(pA, pB, pC, publicInputs)) revert InvalidProof();

        _spentNullifiers[electionId][nullifier] = true;
        ballots.push(NaiveBallot({ciphertext: ciphertext, nullifier: nullifier}));

        emit NaiveBallotAccepted(electionId, nullifier);
    }
}
