// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DisplacementLedger
/// @notice Immutable on-chain record of community displacement events
/// @dev Lex-0: active displacement blocks CarbonCreditNFT minting
contract DisplacementLedger {

    struct DisplacementEvent {
        string  communityId;
        string  communityName;
        string  region;
        string  landId;
        string  displacementType;
        string  status;
        string  incidentDate;
        bool    fpicViolated;
        uint256 peopleAffected;
        bytes32 recordHash;
        bytes32 evidenceIpfs;
        uint256 timestamp;
    }

    mapping(bytes32 => DisplacementEvent) public events;
    mapping(bytes32 => bool) public carbonBlocked; // zoneHash => blocked
    bytes32[] public eventIndex;

    address public immutable EDEN_ORACLE;

    event DisplacementRecorded(
        bytes32 indexed eventId,
        string  communityName,
        string  displacementType,
        bool    fpicViolated,
        uint256 peopleAffected,
        uint256 timestamp
    );
    event CarbonBlockApplied(bytes32 indexed zoneHash, string reason);
    event StatusUpdated(bytes32 indexed eventId, string newStatus);

    modifier onlyOracle() {
        require(msg.sender == EDEN_ORACLE, "Only EDEN oracle");
        _;
    }

    constructor(address oracle) {
        EDEN_ORACLE = oracle;
    }

    function logDisplacement(
        bytes32 eventId,
        string calldata communityId,
        string calldata communityName,
        string calldata region,
        string calldata landId,
        string calldata displacementType,
        string calldata incidentDate,
        bool   fpicViolated,
        uint256 peopleAffected,
        bytes32 recordHash,
        bytes32 evidenceIpfs,
        bytes32 zoneHash
    ) external onlyOracle {
        events[eventId] = DisplacementEvent({
            communityId:      communityId,
            communityName:    communityName,
            region:           region,
            landId:           landId,
            displacementType: displacementType,
            status:           "REPORTED",
            incidentDate:     incidentDate,
            fpicViolated:     fpicViolated,
            peopleAffected:   peopleAffected,
            recordHash:       recordHash,
            evidenceIpfs:     evidenceIpfs,
            timestamp:        block.timestamp
        });
        eventIndex.push(eventId);

        // Lex-0: block carbon credits on this zone immediately
        if (!carbonBlocked[zoneHash]) {
            carbonBlocked[zoneHash] = true;
            emit CarbonBlockApplied(zoneHash, "Active displacement event");
        }

        emit DisplacementRecorded(
            eventId, communityName, displacementType,
            fpicViolated, peopleAffected, block.timestamp
        );
    }

    function updateStatus(bytes32 eventId, string calldata newStatus)
        external onlyOracle
    {
        require(bytes(events[eventId].communityId).length > 0, "Event not found");
        events[eventId].status = newStatus;
        emit StatusUpdated(eventId, newStatus);
    }

    /// @notice Called by CarbonCreditNFT.sol before minting
    function isCarbonBlocked(bytes32 zoneHash) external view returns (bool) {
        return carbonBlocked[zoneHash];
    }

    function totalEvents() external view returns (uint256) {
        return eventIndex.length;
    }
}
