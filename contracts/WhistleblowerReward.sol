// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WhistleblowerReward
/// @notice Anonymous bounty payments for tip submissions that lead to
///         verified fraud, intrusion, or displacement findings.
///         Whistleblower identity is never stored on-chain.
contract WhistleblowerReward {

    enum TipStatus { PENDING, VERIFIED, REJECTED, PAID }

    struct Tip {
        bytes32 tipHash;         // Hash of tip content — never the content itself
        string  tipType;         // "fraud" | "intrusion" | "displacement" | "poaching"
        TipStatus status;
        uint256 rewardWei;
        uint256 submittedAt;
        uint256 verifiedAt;
        bool    paid;
    }

    mapping(bytes32 => Tip) public tips;
    bytes32[] public tipIndex;

    address public immutable EDEN_ORACLE;
    address public immutable TREASURY;

    uint256 public rewardFraud       = 0.5 ether;
    uint256 public rewardIntrusion   = 0.3 ether;
    uint256 public rewardDisplacement= 0.5 ether;
    uint256 public rewardPoaching    = 0.2 ether;

    event TipSubmitted(bytes32 indexed tipHash, string tipType, uint256 timestamp);
    event TipVerified(bytes32 indexed tipHash, uint256 rewardWei);
    event RewardPaid(bytes32 indexed tipHash, uint256 amount);
    event TipRejected(bytes32 indexed tipHash);

    modifier onlyOracle() {
        require(msg.sender == EDEN_ORACLE, "Only EDEN oracle");
        _;
    }

    constructor(address oracle, address treasury) payable {
        EDEN_ORACLE = oracle;
        TREASURY    = treasury;
    }

    /// @notice Submit a tip hash (content stored off-chain by EDEN)
    function submitTip(bytes32 tipHash, string calldata tipType)
        external onlyOracle
    {
        require(tips[tipHash].submittedAt == 0, "Tip already exists");
        tips[tipHash] = Tip({
            tipHash:      tipHash,
            tipType:      tipType,
            status:       TipStatus.PENDING,
            rewardWei:    _rewardFor(tipType),
            submittedAt:  block.timestamp,
            verifiedAt:   0,
            paid:         false
        });
        tipIndex.push(tipHash);
        emit TipSubmitted(tipHash, tipType, block.timestamp);
    }

    /// @notice Oracle marks tip as verified after EDEN confirms the finding
    function verifyTip(bytes32 tipHash) external onlyOracle {
        Tip storage tip = tips[tipHash];
        require(tip.submittedAt > 0, "Tip not found");
        require(tip.status == TipStatus.PENDING, "Not pending");
        tip.status     = TipStatus.VERIFIED;
        tip.verifiedAt = block.timestamp;
        emit TipVerified(tipHash, tip.rewardWei);
    }

    /// @notice Pay reward to anonymous recipient address (provided by EDEN off-chain)
    function payReward(bytes32 tipHash, address payable recipient)
        external onlyOracle
    {
        Tip storage tip = tips[tipHash];
        require(tip.status == TipStatus.VERIFIED, "Not verified");
        require(!tip.paid, "Already paid");
        require(address(this).balance >= tip.rewardWei, "Insufficient treasury");
        tip.paid   = true;
        tip.status = TipStatus.PAID;
        recipient.transfer(tip.rewardWei);
        emit RewardPaid(tipHash, tip.rewardWei);
    }

    function rejectTip(bytes32 tipHash) external onlyOracle {
        tips[tipHash].status = TipStatus.REJECTED;
        emit TipRejected(tipHash);
    }

    function _rewardFor(string memory tipType) internal view returns (uint256) {
        bytes32 h = keccak256(bytes(tipType));
        if (h == keccak256("fraud"))        return rewardFraud;
        if (h == keccak256("intrusion"))    return rewardIntrusion;
        if (h == keccak256("displacement")) return rewardDisplacement;
        return rewardPoaching;
    }

    function totalTips() external view returns (uint256) { return tipIndex.length; }
    receive() external payable {}
}
