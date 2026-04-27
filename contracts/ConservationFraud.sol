// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConservationFraud
/// @notice Stores satellite-backed fraud assessments for conservation claims
/// @dev FRAUDULENT verdict blocks CarbonCreditNFT minting via Lex-0
contract ConservationFraud {

    enum Verdict { VERIFIED, SUSPICIOUS, FRAUDULENT, INSUFFICIENT_DATA }

    struct FraudRecord {
        string  entityId;
        string  entityName;
        string  regionName;
        string  claimPeriodStart;
        string  claimPeriodEnd;
        uint256 carbonCreditsIssued;
        uint8   fraudScore;          // 0-100
        Verdict verdict;
        int16   ndviDeltaBps;        // basis points (x10000), signed
        uint16  infraAnomalies;
        bytes32 evidenceIpfs;
        uint256 timestamp;
    }

    mapping(bytes32 => FraudRecord) public records;   // entityHash => record
    mapping(bytes32 => bool)        public mintBlocked; // zoneHash => blocked
    bytes32[] public recordIndex;

    address public immutable EDEN_ORACLE;

    event FraudAssessed(
        bytes32 indexed entityHash,
        string  entityName,
        uint8   fraudScore,
        Verdict verdict,
        bytes32 evidenceIpfs,
        uint256 timestamp
    );
    event MintBlocked(bytes32 indexed zoneHash, string entityName, uint8 score);

    modifier onlyOracle() {
        require(msg.sender == EDEN_ORACLE, "Only EDEN oracle");
        _;
    }

    constructor(address oracle) {
        EDEN_ORACLE = oracle;
    }

    function logFraudAssessment(
        bytes32 entityHash,
        string  calldata entityId,
        string  calldata entityName,
        string  calldata regionName,
        string  calldata claimPeriodStart,
        string  calldata claimPeriodEnd,
        uint256 carbonCreditsIssued,
        uint8   fraudScore,
        Verdict verdict,
        int16   ndviDeltaBps,
        uint16  infraAnomalies,
        bytes32 evidenceIpfs,
        bytes32 zoneHash
    ) external onlyOracle {
        records[entityHash] = FraudRecord({
            entityId:            entityId,
            entityName:          entityName,
            regionName:          regionName,
            claimPeriodStart:    claimPeriodStart,
            claimPeriodEnd:      claimPeriodEnd,
            carbonCreditsIssued: carbonCreditsIssued,
            fraudScore:          fraudScore,
            verdict:             verdict,
            ndviDeltaBps:        ndviDeltaBps,
            infraAnomalies:      infraAnomalies,
            evidenceIpfs:        evidenceIpfs,
            timestamp:           block.timestamp
        });
        recordIndex.push(entityHash);

        // Lex-0: block carbon minting for FRAUDULENT verdicts
        if (verdict == Verdict.FRAUDULENT && !mintBlocked[zoneHash]) {
            mintBlocked[zoneHash] = true;
            emit MintBlocked(zoneHash, entityName, fraudScore);
        }

        emit FraudAssessed(entityHash, entityName, fraudScore,
                           verdict, evidenceIpfs, block.timestamp);
    }

    function isMintBlocked(bytes32 zoneHash) external view returns (bool) {
        return mintBlocked[zoneHash];
    }

    function getVerdict(bytes32 entityHash) external view returns (Verdict) {
        return records[entityHash].verdict;
    }

    function totalRecords() external view returns (uint256) {
        return recordIndex.length;
    }
}
