// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./EHRAccessControl.sol";

/**
 * @title EHRIntegrityRegistry
 * @dev Anchors cryptographic metadata, SHA-256 hashes, and security breach incidents on-chain.
 * CRITICAL SCIENTIFIC GUARANTEE: Sensitive plaintext EHR data is strictly stored off-chain.
 * Only cryptographic digests, algorithm IDs, access policies, and audit receipts exist on-chain.
 */
contract EHRIntegrityRegistry {
    address public admin;
    EHRAccessControl public accessControl;

    struct EHRMetadata {
        string recordId;
        bytes32 payloadHash;
        uint256 timestamp;
        address registeredBy;
        string encryptionAlgorithm;
        string keyId;
        string accessPolicy;
        bool exists;
    }

    struct SecurityIncident {
        string incidentId;
        string recordId;
        string attackType;
        string severity;
        uint256 confidenceScore; // e.g. 9942 for 99.42%
        uint256 timestamp;
        address reporter;
        bool integrityBreached;
        string recommendedAction;
        string responseStatus; // "ACKNOWLEDGED", "CONTAINED", "CLOSED"
    }

    mapping(string => EHRMetadata) private ehrRecords;
    mapping(string => SecurityIncident) private incidents;
    string[] private recordIds;
    string[] private incidentIds;

    // Events
    event EHRRegistered(
        string indexed recordId,
        bytes32 indexed payloadHash,
        address indexed registeredBy,
        uint256 timestamp,
        string encryptionAlgorithm,
        string keyId
    );

    event IntegrityVerified(string indexed recordId, bool isAuthentic, uint256 timestamp);
    event IntegrityFailure(string indexed recordId, bytes32 expectedHash, bytes32 actualHash, uint256 timestamp);

    event SecurityIncidentLogged(
        string indexed incidentId,
        string indexed recordId,
        string attackType,
        string severity,
        uint256 confidence,
        uint256 timestamp
    );

    event BreachDetected(
        string indexed incidentId,
        string indexed recordId,
        string attackType,
        string severity,
        string recommendedAction
    );

    event ResponseStatusUpdated(string indexed incidentId, string newStatus, uint256 timestamp);

    constructor(address accessControlAddress) {
        admin = msg.sender;
        accessControl = EHRAccessControl(accessControlAddress);
    }

    function registerEHR(
        string memory recordId,
        bytes32 payloadHash,
        string memory algorithm,
        string memory keyId,
        string memory accessPolicy
    ) public {
        require(!ehrRecords[recordId].exists, "EHR Record ID already registered");
        require(payloadHash != bytes32(0), "Invalid payload hash");

        ehrRecords[recordId] = EHRMetadata({
            recordId: recordId,
            payloadHash: payloadHash,
            timestamp: block.timestamp,
            registeredBy: msg.sender,
            encryptionAlgorithm: algorithm,
            keyId: keyId,
            accessPolicy: accessPolicy,
            exists: true
        });
        recordIds.push(recordId);

        emit EHRRegistered(recordId, payloadHash, msg.sender, block.timestamp, algorithm, keyId);
    }

    function verifyIntegrity(
        string memory recordId,
        bytes32 recomputedHash
    ) public returns (bool, string memory) {
        require(ehrRecords[recordId].exists, "EHR Record not found on blockchain");

        bytes32 storedHash = ehrRecords[recordId].payloadHash;
        if (storedHash == recomputedHash) {
            emit IntegrityVerified(recordId, true, block.timestamp);
            return (true, "INTEGRITY_VERIFIED_AUTHENTIC");
        } else {
            emit IntegrityFailure(recordId, storedHash, recomputedHash, block.timestamp);
            return (false, "TAMPER_DETECTED_HASH_MISMATCH");
        }
    }

    function recordIncident(
        string memory incidentId,
        string memory recordId,
        string memory attackType,
        string memory severity,
        uint256 confidenceScore,
        bool integrityBreached,
        string memory recommendedAction
    ) public {
        require(bytes(incidentId).length > 0, "Empty incident ID");

        incidents[incidentId] = SecurityIncident({
            incidentId: incidentId,
            recordId: recordId,
            attackType: attackType,
            severity: severity,
            confidenceScore: confidenceScore,
            timestamp: block.timestamp,
            reporter: msg.sender,
            integrityBreached: integrityBreached,
            recommendedAction: recommendedAction,
            responseStatus: "ACKNOWLEDGED"
        });
        incidentIds.push(incidentId);

        emit SecurityIncidentLogged(incidentId, recordId, attackType, severity, confidenceScore, block.timestamp);
        emit BreachDetected(incidentId, recordId, attackType, severity, recommendedAction);
    }

    function updateResponseStatus(string memory incidentId, string memory newStatus) public {
        require(bytes(incidents[incidentId].incidentId).length > 0, "Incident not found");
        incidents[incidentId].responseStatus = newStatus;
        emit ResponseStatusUpdated(incidentId, newStatus, block.timestamp);
    }

    function getEHRMetadata(string memory recordId) public view returns (
        bytes32 payloadHash,
        uint256 timestamp,
        address registeredBy,
        string memory algorithm,
        string memory keyId,
        string memory accessPolicy
    ) {
        require(ehrRecords[recordId].exists, "Record not found");
        EHRMetadata memory m = ehrRecords[recordId];
        return (m.payloadHash, m.timestamp, m.registeredBy, m.encryptionAlgorithm, m.keyId, m.accessPolicy);
    }

    function getIncident(string memory incidentId) public view returns (
        string memory recordId,
        string memory attackType,
        string memory severity,
        uint256 confidenceScore,
        uint256 timestamp,
        bool integrityBreached,
        string memory recommendedAction,
        string memory responseStatus
    ) {
        SecurityIncident memory inc = incidents[incidentId];
        return (
            inc.recordId,
            inc.attackType,
            inc.severity,
            inc.confidenceScore,
            inc.timestamp,
            inc.integrityBreached,
            inc.recommendedAction,
            inc.responseStatus
        );
    }

    function getTotalRecords() public view returns (uint256) {
        return recordIds.length;
    }

    function getTotalIncidents() public view returns (uint256) {
        return incidentIds.length;
    }
}
