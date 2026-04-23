// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface ICrossGroupBallotBox {
    enum Phase {
        IDLE,
        VOTING,
        TALLYING,
        FINALIZED
    }

    struct ElectionInitParams {
        bytes publicKey;
        bytes32 merkleRoot;
        uint256 threshold;
        uint64 votingDeadlineBlock;
        uint64 tallyDeadlineBlock;
    }

    struct ElectionParams {
        bytes publicKey;
        bytes32 merkleRoot;
        uint256 threshold;
        uint256 electionIndex;
        uint256 nullifierDomain;
        uint64 votingDeadlineBlock;
        uint64 tallyDeadlineBlock;
    }

    struct BallotRecord {
        bytes ciphertext;
        bytes32 voteHash;
        uint256 nullifier;
        bytes32 validityProofCommitment;
        uint64 blockNumber;
    }

    struct AggregateRecord {
        bytes aggregateCiphertext;
        bytes32 aggregateCommitment;
        uint256 ballotCount;
        uint64 publishedBlock;
    }

    struct ShareRecord {
        bytes share;
        bytes32 shareProofMetadata;
        address submitter;
        uint64 blockNumber;
    }

    struct ResultRecord {
        bytes resultData;
        bytes32 aggregateCommitment;
        uint256 sharesCollected;
        uint64 finalizedBlock;
    }

    struct ResultRecordInput {
        bytes resultData;
        bytes32 aggregateCommitment;
    }

    event ElectionInitialized(uint256 indexed electionIndex, bytes32 indexed merkleRoot, uint256 threshold);
    event BallotAccepted(uint256 indexed electionIndex, uint256 indexed nullifier, bytes32 voteHash);
    event VotingClosed(uint256 indexed electionIndex);
    event AggregatePublished(uint256 indexed electionIndex, bytes32 indexed aggregateCommitment);
    event ShareSubmitted(uint256 indexed electionIndex, address indexed submitter, bytes32 proofMetadata);
    event ElectionFinalized(uint256 indexed electionIndex, bytes32 indexed aggregateCommitment, uint256 sharesCollected);

    error InvalidPhase(Phase expected, Phase actual);
    error InvalidVerifier();
    error InvalidPublicKey();
    error InvalidMerkleRoot();
    error InvalidThreshold();
    error InvalidDeadline();
    error InvalidCiphertext();
    error InvalidValidityProof();
    error InvalidProof();
    error InvalidPublicInputs();
    error NullifierAlreadySpent();
    error InvalidAggregate();
    error AggregateAlreadyPublished();
    error AggregateNotPublished();
    error AggregateCommitmentMismatch();
    error InvalidShare();
    error InvalidShareProofMetadata();
    error ShareAlreadySubmitted();
    error VotingPeriodClosed();
    error VotingStillOpen();
    error TallyClosed();
    error InsufficientShares(uint256 required, uint256 actual);
    error NotCommitteeMember();
    error CommitteeMemberAlreadyRegistered();
    error CommitteeNotEmpty();

    event CommitteeMemberAdded(address indexed member);
    event CommitteeMemberRemoved(address indexed member);

    function registerCommitteeMember(address member) external;
    function removeCommitteeMember(address member) external;
    function isCommitteeMember(address member) external view returns (bool);
    function committeeSize() external view returns (uint256);

    function initElection(ElectionInitParams calldata params) external;

    function castBallot(
        bytes calldata ciphertext,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes calldata validityProof,
        uint256[36] calldata publicInputs
    ) external;

    function closeVoting() external;

    function publishAggregate(bytes calldata aggregate) external;

    function submitShare(bytes calldata share, bytes32 aggregateCommitment, bytes32 proofMetadata) external;

    function finalize(ResultRecordInput calldata resultRecord) external;

    function getTranscript()
        external
        view
        returns (
            ElectionParams memory params,
            AggregateRecord memory aggregate,
            ResultRecord memory result,
            Phase phase,
            uint256 ballotCount,
            uint256 shareCount
        );

    function getBallot(uint256 index) external view returns (BallotRecord memory);
    function getShare(uint256 index) external view returns (ShareRecord memory);
}
