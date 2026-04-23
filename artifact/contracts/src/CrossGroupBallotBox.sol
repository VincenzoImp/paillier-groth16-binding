// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ICrossGroupBallotBox} from "./interfaces/ICrossGroupBallotBox.sol";
import {ICrossGroupVerifier} from "./interfaces/ICrossGroupVerifier.sol";
import {IBallotValidityVerifier} from "./interfaces/IBallotValidityVerifier.sol";

/// @title CrossGroupBallotBox
/// @notice Minimal bulletin-board contract for ballots, aggregates, shares, and finalization.
/// @dev The contract verifies that the ciphertext bytes match the 32 public limb inputs committed by the proof.
contract CrossGroupBallotBox is ICrossGroupBallotBox, Ownable, Pausable {
    uint256 internal constant CIPHERTEXT_BYTES = 768;
    uint256 internal constant LIMB_BYTES = 24;
    uint256 internal constant LIMB_COUNT = 32;
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 internal constant NULLIFIER_DOMAIN_TAG = keccak256("cgbl/nullifier-domain/v1");

    ICrossGroupVerifier public immutable verifier;
    IBallotValidityVerifier public immutable validityVerifier;
    Phase public phase;
    uint256 public currentElectionIndex;

    ElectionParams internal _params;
    AggregateRecord internal _aggregate;
    ResultRecord internal _result;

    BallotRecord[] internal _ballots;
    ShareRecord[] internal _shares;

    mapping(uint256 => mapping(uint256 => bool)) internal _spentNullifiers;
    mapping(uint256 => mapping(address => bool)) internal _shareSubmitted;

    // Committee registry: only registered members can submit decryption shares
    mapping(address => bool) internal _committeeMembers;
    address[] internal _committeeMemberList;

    modifier onlyCommitteeMember() {
        if (!_committeeMembers[msg.sender]) revert NotCommitteeMember();
        _;
    }

    modifier onlyPhase(Phase expected) {
        if (phase != expected) revert InvalidPhase(expected, phase);
        _;
    }

    constructor(address verifierAddress, address validityVerifierAddress, address initialOwner) Ownable(initialOwner) {
        if (verifierAddress == address(0)) revert InvalidVerifier();
        verifier = ICrossGroupVerifier(verifierAddress);
        validityVerifier = IBallotValidityVerifier(validityVerifierAddress);
        phase = Phase.IDLE;
    }

    function registerCommitteeMember(address member) external onlyOwner {
        if (phase == Phase.VOTING || phase == Phase.TALLYING) revert InvalidPhase(Phase.IDLE, phase);
        if (member == address(0)) revert NotCommitteeMember();
        if (_committeeMembers[member]) revert CommitteeMemberAlreadyRegistered();
        _committeeMembers[member] = true;
        _committeeMemberList.push(member);
        emit CommitteeMemberAdded(member);
    }

    function removeCommitteeMember(address member) external onlyOwner {
        if (phase == Phase.VOTING || phase == Phase.TALLYING) revert InvalidPhase(Phase.IDLE, phase);
        if (!_committeeMembers[member]) revert NotCommitteeMember();
        _committeeMembers[member] = false;
        for (uint256 i = 0; i < _committeeMemberList.length; i++) {
            if (_committeeMemberList[i] == member) {
                _committeeMemberList[i] = _committeeMemberList[_committeeMemberList.length - 1];
                _committeeMemberList.pop();
                break;
            }
        }
        emit CommitteeMemberRemoved(member);
    }

    function isCommitteeMember(address member) external view returns (bool) {
        return _committeeMembers[member];
    }

    function committeeSize() external view returns (uint256) {
        return _committeeMemberList.length;
    }

    function initElection(ElectionInitParams calldata params) external onlyOwner {
        if (phase != Phase.IDLE && phase != Phase.FINALIZED) revert InvalidPhase(Phase.IDLE, phase);
        if (params.publicKey.length == 0) revert InvalidPublicKey();
        if (params.merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (params.threshold == 0 || params.threshold > _committeeMemberList.length) revert InvalidThreshold();
        if (params.votingDeadlineBlock <= block.number || params.tallyDeadlineBlock <= params.votingDeadlineBlock) {
            revert InvalidDeadline();
        }

        delete _ballots;
        delete _shares;
        delete _aggregate;
        delete _result;

        uint256 nextElectionIndex = currentElectionIndex + 1;
        uint256 nextNullifierDomain = _computeNullifierDomain(nextElectionIndex);

        currentElectionIndex = nextElectionIndex;
        _params = ElectionParams({
            publicKey: params.publicKey,
            merkleRoot: params.merkleRoot,
            threshold: params.threshold,
            electionIndex: nextElectionIndex,
            nullifierDomain: nextNullifierDomain,
            votingDeadlineBlock: params.votingDeadlineBlock,
            tallyDeadlineBlock: params.tallyDeadlineBlock
        });
        phase = Phase.VOTING;

        emit ElectionInitialized(nextElectionIndex, params.merkleRoot, params.threshold);
    }

    function castBallot(
        bytes calldata ciphertext,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes calldata validityProof,
        uint256[36] calldata publicInputs
    ) external onlyPhase(Phase.VOTING) whenNotPaused {
        if (block.number > _params.votingDeadlineBlock) revert VotingPeriodClosed();
        // CRITICAL: enforce canonical fixed-width serialization.
        // Variable-length acceptance would break injectivity of the limb
        // decomposition (e.g. 0x01 and 0x0001 would yield identical limbs).
        if (ciphertext.length != CIPHERTEXT_BYTES) revert InvalidCiphertext();
        // Validity proof is required only when a validity verifier is configured
        if (address(validityVerifier) != address(0) && validityProof.length == 0) revert InvalidValidityProof();
        if (publicInputs[0] != uint256(_params.merkleRoot)) revert InvalidPublicInputs();
        if (publicInputs[2] != _params.nullifierDomain) revert InvalidPublicInputs();

        uint256 nullifier = publicInputs[1];
        if (_spentNullifiers[_params.electionIndex][nullifier]) revert NullifierAlreadySpent();

        _assertCiphertextMatchesPublicLimbs(ciphertext, publicInputs);
        _assertValidityProof(ciphertext, validityProof);

        if (!verifier.verifyProof(pA, pB, pC, publicInputs)) revert InvalidProof();

        _spentNullifiers[_params.electionIndex][nullifier] = true;

        bytes32 voteHash = bytes32(publicInputs[3]);
        _ballots.push(
            BallotRecord({
                ciphertext: ciphertext,
                voteHash: voteHash,
                nullifier: nullifier,
                validityProofCommitment: keccak256(validityProof),
                blockNumber: uint64(block.number)
            })
        );

        emit BallotAccepted(_params.electionIndex, nullifier, voteHash);
    }

    function closeVoting() external onlyOwner onlyPhase(Phase.VOTING) {
        if (block.number <= _params.votingDeadlineBlock) revert VotingStillOpen();
        phase = Phase.TALLYING;
        emit VotingClosed(_params.electionIndex);
    }

    function publishAggregate(bytes calldata aggregate) external onlyOwner onlyPhase(Phase.TALLYING) {
        if (block.number > _params.tallyDeadlineBlock) revert TallyClosed();
        // Enforce canonical fixed-width serialization for aggregate,
        // matching the ballot-side requirement. This ensures that the
        // transcript-derived aggregate comparison is well-defined.
        if (aggregate.length != CIPHERTEXT_BYTES) revert InvalidAggregate();
        if (_aggregate.aggregateCommitment != bytes32(0)) revert AggregateAlreadyPublished();

        _aggregate = AggregateRecord({
            aggregateCiphertext: aggregate,
            aggregateCommitment: keccak256(aggregate),
            ballotCount: _ballots.length,
            publishedBlock: uint64(block.number)
        });

        emit AggregatePublished(_params.electionIndex, _aggregate.aggregateCommitment);
    }

    function submitShare(bytes calldata share, bytes32 aggregateCommitment, bytes32 proofMetadata)
        external
        onlyPhase(Phase.TALLYING)
        onlyCommitteeMember
    {
        if (block.number > _params.tallyDeadlineBlock) revert TallyClosed();
        if (_aggregate.aggregateCommitment == bytes32(0)) revert AggregateNotPublished();
        if (aggregateCommitment != _aggregate.aggregateCommitment) revert AggregateCommitmentMismatch();
        if (share.length == 0) revert InvalidShare();
        if (proofMetadata == bytes32(0)) revert InvalidShareProofMetadata();
        if (_shareSubmitted[_params.electionIndex][msg.sender]) revert ShareAlreadySubmitted();

        _shareSubmitted[_params.electionIndex][msg.sender] = true;
        _shares.push(
            ShareRecord({
                share: share,
                shareProofMetadata: proofMetadata,
                submitter: msg.sender,
                blockNumber: uint64(block.number)
            })
        );

        emit ShareSubmitted(_params.electionIndex, msg.sender, proofMetadata);
    }

    function finalize(ResultRecordInput calldata resultRecord) external onlyOwner onlyPhase(Phase.TALLYING) {
        if (_aggregate.aggregateCommitment == bytes32(0)) revert AggregateNotPublished();
        if (resultRecord.aggregateCommitment != _aggregate.aggregateCommitment) revert AggregateCommitmentMismatch();
        if (_shares.length < _params.threshold) revert InsufficientShares(_params.threshold, _shares.length);

        _result = ResultRecord({
            resultData: resultRecord.resultData,
            aggregateCommitment: resultRecord.aggregateCommitment,
            sharesCollected: _shares.length,
            finalizedBlock: uint64(block.number)
        });
        phase = Phase.FINALIZED;

        emit ElectionFinalized(_params.electionIndex, resultRecord.aggregateCommitment, _shares.length);
    }

    function getTranscript()
        external
        view
        returns (
            ElectionParams memory params,
            AggregateRecord memory aggregate,
            ResultRecord memory result,
            Phase currentPhase,
            uint256 ballotCount,
            uint256 shareCount
        )
    {
        return (_params, _aggregate, _result, phase, _ballots.length, _shares.length);
    }

    function getBallot(uint256 index) external view returns (BallotRecord memory) {
        return _ballots[index];
    }

    function getShare(uint256 index) external view returns (ShareRecord memory) {
        return _shares[index];
    }

    function _assertCiphertextMatchesPublicLimbs(bytes calldata ciphertext, uint256[36] calldata publicInputs) internal pure {
        for (uint256 limbIndex = 0; limbIndex < LIMB_COUNT; ++limbIndex) {
            if (_extractLimb(ciphertext, limbIndex) != publicInputs[4 + limbIndex]) revert InvalidPublicInputs();
        }
    }

    function _assertValidityProof(bytes calldata ciphertext, bytes calldata validityProof) internal view {
        if (address(validityVerifier) == address(0)) {
            return;
        }

        if (!validityVerifier.verifyValidity(ciphertext, validityProof)) revert InvalidValidityProof();
    }

    function _extractLimb(bytes calldata ciphertext, uint256 limbIndex) internal pure returns (uint256 limb) {
        // ciphertext.length == CIPHERTEXT_BYTES is enforced by castBallot,
        // so no padding logic is needed: the decomposition is bijective.
        uint256 limbStart = limbIndex * LIMB_BYTES;
        for (uint256 i = 0; i < LIMB_BYTES; ++i) {
            limb = (limb << 8) | uint8(ciphertext[limbStart + i]);
        }
    }

    function _computeNullifierDomain(uint256 electionIndex) internal view returns (uint256) {
        // Domain-separate nullifiers across protocol versions, chains, deployments, and
        // election rounds before reducing into the SNARK scalar field.
        return uint256(
            keccak256(
                abi.encode(
                    NULLIFIER_DOMAIN_TAG,
                    block.chainid,
                    address(this),
                    electionIndex
                )
            )
        ) % SNARK_SCALAR_FIELD;
    }
}
