// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CorporateIntrusion
/// @notice Immutable log of unauthorized corporate/investor infrastructure
///         detected inside protected wildlife zones and ancestral land
contract CorporateIntrusion {

    enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    struct IntrusionEvent {
        string  eventId;
        string  zoneId;
        string  zoneName;
        string  zoneType;
        string  intrusionType;     // road / structure / clearing / mining
        Severity severity;
        int64   locationLon;       // degrees * 1e6, signed
        int64   locationLat;
        uint256 areaM2;
        uint16  confidenceBps;     // basis points 0-10000
        string  suspectedEntity;
        string  companyRegNumber;
        bytes32 evidenceIpfs;
        uint256 timestamp;
    }

    mapping(bytes32 => IntrusionEvent) public events;
    bytes32[] public eventIndex;

    address public immutable EDEN_ORACLE;

    event IntrusionDetected(
        bytes32 indexed eventHash,
        string  zoneId,
        string  intrusionType,
        Severity severity,
        string  suspectedEntity,
        bytes32 evidenceIpfs,
        uint256 timestamp
    );

    modifier onlyOracle() {
        require(msg.sender == EDEN_ORACLE, "Only EDEN oracle");
        _;
    }

    constructor(address oracle) {
        EDEN_ORACLE = oracle;
    }

    function logIntrusion(
        bytes32  eventHash,
        string   calldata eventId,
        string   calldata zoneId,
        string   calldata zoneName,
        string   calldata zoneType,
        string   calldata intrusionType,
        Severity severity,
        int64    locationLon,
        int64    locationLat,
        uint256  areaM2,
        uint16   confidenceBps,
        string   calldata suspectedEntity,
        string   calldata companyRegNumber,
        bytes32  evidenceIpfs
    ) external onlyOracle {
        events[eventHash] = IntrusionEvent({
            eventId:          eventId,
            zoneId:           zoneId,
            zoneName:         zoneName,
            zoneType:         zoneType,
            intrusionType:    intrusionType,
            severity:         severity,
            locationLon:      locationLon,
            locationLat:      locationLat,
            areaM2:           areaM2,
            confidenceBps:    confidenceBps,
            suspectedEntity:  suspectedEntity,
            companyRegNumber: companyRegNumber,
            evidenceIpfs:     evidenceIpfs,
            timestamp:        block.timestamp
        });
        eventIndex.push(eventHash);

        emit IntrusionDetected(eventHash, zoneId, intrusionType,
                               severity, suspectedEntity, evidenceIpfs, block.timestamp);
    }

    function totalEvents() external view returns (uint256) {
        return eventIndex.length;
    }
}
