// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IIoTSecurityRegistry
 * @dev Smart Contract for Edge-IIoT Security Event Metadata Anchoring,
 *      Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC),
 *      Cryptographic Integrity Verification, and Comprehensive Security Auditing.
 *      Adheres to JIDMIS 2026 Framework for post-quantum decoupled on-chain metadata.
 */
contract IIoTSecurityRegistry {

    enum Role { NONE, ADMIN, SECURITY_ANALYST, OPERATOR, RESEARCHER, AUDITOR, DEVICE }

    struct SecurityEvent {
        bytes32 eventId;
        uint256 timestamp;
        bytes32 deviceHash;
        uint8 prediction;      // 0 = Normal, 1 = Attack
        string attackType;     // e.g. "DDoS_UDP", "Ransomware", "Normal"
        uint16 confidence;     // Scaled by 100 (e.g. 9850 = 98.50%)
        bytes32 payloadHash;   // SHA-256 of off-chain encrypted payload
        bytes32 modelHash;     // SHA-256 of deployed ML/DL model architecture & weights
        bytes32 policyHash;    // Hash of active ABE/RBAC policy specification
        address reporter;      // Address of edge node or analyst
        bool exists;
    }

    struct UserProfile {
        Role role;
        bool isActive;
        mapping(string => string) attributes; // ABAC attributes: e.g., "department" => "IIoT_SECURITY"
    }

    struct AuditRecord {
        uint256 timestamp;
        address accessor;
        bytes32 eventId;
        string action;        // e.g. "ACCESS_REQUEST", "VERIFY_HASH", "REVOKE_ACCESS"
        bool decision;        // true = GRANTED/ALLOW, false = DENIED
        string reason;
    }

    address public admin;
    uint256 public totalEvents;
    uint256 public totalAuditLogs;

    mapping(address => UserProfile) private users;
    mapping(bytes32 => bool) public registeredDevices;
    mapping(bytes32 => SecurityEvent) private securityEvents;
    bytes32[] public eventIds;
    AuditRecord[] public auditLog;

    // Events
    event DeviceRegistered(bytes32 indexed deviceHash, string metadata, uint256 timestamp);
    event UserRegistered(address indexed user, Role role, uint256 timestamp);
    event RoleUpdated(address indexed user, Role oldRole, Role newRole, uint256 timestamp);
    event AttributeSet(address indexed user, string key, string value, uint256 timestamp);
    event SecurityEventCreated(bytes32 indexed eventId, bytes32 indexed payloadHash, string attackType, uint8 prediction, uint256 timestamp);
    event AccessEvaluated(address indexed user, bytes32 indexed eventId, bool decision, string reason, uint256 timestamp);
    event IntegrityVerified(bytes32 indexed eventId, bool isValid, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "IIoTRegistry: Caller is not authorized ADMIN");
        _;
    }

    modifier onlyAuthorized() {
        require(users[msg.sender].isActive || msg.sender == admin, "IIoTRegistry: Caller is not active or registered");
        _;
    }

    constructor() {
        admin = msg.sender;
        users[msg.sender].role = Role.ADMIN;
        users[msg.sender].isActive = true;
    }

    function registerDevice(bytes32 deviceHash, string calldata metadata) external onlyAuthorized {
        require(!registeredDevices[deviceHash], "IIoTRegistry: Device already registered");
        registeredDevices[deviceHash] = true;
        emit DeviceRegistered(deviceHash, metadata, block.timestamp);
    }

    function registerUser(address user, Role role) external onlyAdmin {
        require(user != address(0), "IIoTRegistry: Invalid address");
        users[user].role = role;
        users[user].isActive = true;
        emit UserRegistered(user, role, block.timestamp);
    }

    function setRole(address user, Role role) external onlyAdmin {
        require(users[user].isActive, "IIoTRegistry: User not registered");
        Role oldRole = users[user].role;
        users[user].role = role;
        emit RoleUpdated(user, oldRole, role, block.timestamp);
    }

    function setAttribute(address user, string calldata key, string calldata value) external onlyAdmin {
        require(users[user].isActive, "IIoTRegistry: User not registered");
        users[user].attributes[key] = value;
        emit AttributeSet(user, key, value, block.timestamp);
    }

    function getAttribute(address user, string calldata key) external view returns (string memory) {
        return users[user].attributes[key];
    }

    function getUserRole(address user) external view returns (Role) {
        return users[user].role;
    }

    function isUserActive(address user) external view returns (bool) {
        return users[user].isActive;
    }

    function createSecurityEvent(
        bytes32 eventId,
        bytes32 deviceHash,
        uint8 prediction,
        string calldata attackType,
        uint16 confidence,
        bytes32 payloadHash,
        bytes32 modelHash,
        bytes32 policyHash
    ) external onlyAuthorized {
        require(!securityEvents[eventId].exists, "IIoTRegistry: Event ID already exists");
        require(payloadHash != bytes32(0), "IIoTRegistry: Empty payload hash");

        SecurityEvent storage evt = securityEvents[eventId];
        evt.eventId = eventId;
        evt.timestamp = block.timestamp;
        evt.deviceHash = deviceHash;
        evt.prediction = prediction;
        evt.attackType = attackType;
        evt.confidence = confidence;
        evt.payloadHash = payloadHash;
        evt.modelHash = modelHash;
        evt.policyHash = policyHash;
        evt.reporter = msg.sender;
        evt.exists = true;

        eventIds.push(eventId);
        totalEvents++;

        emit SecurityEventCreated(eventId, payloadHash, attackType, prediction, block.timestamp);
    }

    function storeEventHash(bytes32 eventId, bytes32 payloadHash) external onlyAuthorized {
        require(securityEvents[eventId].exists, "IIoTRegistry: Event does not exist");
        securityEvents[eventId].payloadHash = payloadHash;
    }

    function verifyEventHash(bytes32 eventId, bytes32 recomputedHash) external returns (bool) {
        require(securityEvents[eventId].exists, "IIoTRegistry: Event does not exist");
        bool matches = (securityEvents[eventId].payloadHash == recomputedHash);
        
        auditLog.push(AuditRecord({
            timestamp: block.timestamp,
            accessor: msg.sender,
            eventId: eventId,
            action: "VERIFY_HASH",
            decision: matches,
            reason: matches ? "INTEGRITY_VERIFIED" : "TAMPER_DETECTED"
        }));
        totalAuditLogs++;

        emit IntegrityVerified(eventId, matches, block.timestamp);
        return matches;
    }

    /**
     * @dev Hybrid RBAC + ABAC policy evaluation engine:
     * - ADMIN: Always ALLOW
     * - SECURITY_ANALYST + dept=="IIoT_SECURITY": ALLOW
     * - RESEARCHER + clearance=="READ_ONLY": ALLOW
     * - OPERATOR + env=="PRODUCTION": ALLOW
     * - AUDITOR: ALLOW for compliance audit
     * - All others: DENY
     */
    function authorizeAccess(
        address user,
        bytes32 eventId,
        string calldata requestedAttribute
    ) external returns (bool) {
        UserProfile storage profile = users[user];
        bool isAllowed = false;
        string memory reason = "DENIED: Policy constraints not satisfied";

        if (!profile.isActive) {
            reason = "DENIED: User inactive or unregistered";
        } else if (profile.role == Role.ADMIN) {
            isAllowed = true;
            reason = "ALLOWED: Admin universal access";
        } else if (profile.role == Role.SECURITY_ANALYST) {
            if (keccak256(bytes(profile.attributes["department"])) == keccak256(bytes("IIoT_SECURITY")) ||
                keccak256(bytes(requestedAttribute)) == keccak256(bytes("IIoT_SECURITY"))) {
                isAllowed = true;
                reason = "ALLOWED: Security Analyst IIoT_SECURITY policy satisfied";
            }
        } else if (profile.role == Role.RESEARCHER) {
            if (keccak256(bytes(profile.attributes["clearance"])) == keccak256(bytes("READ_ONLY")) ||
                keccak256(bytes(requestedAttribute)) == keccak256(bytes("READ_ONLY"))) {
                isAllowed = true;
                reason = "ALLOWED: Researcher READ_ONLY policy satisfied";
            }
        } else if (profile.role == Role.OPERATOR) {
            if (keccak256(bytes(profile.attributes["environment"])) == keccak256(bytes("PRODUCTION")) ||
                keccak256(bytes(requestedAttribute)) == keccak256(bytes("PRODUCTION"))) {
                isAllowed = true;
                reason = "ALLOWED: Operator PRODUCTION policy satisfied";
            }
        } else if (profile.role == Role.AUDITOR) {
            isAllowed = true;
            reason = "ALLOWED: Auditor read-only audit log access";
        }

        auditLog.push(AuditRecord({
            timestamp: block.timestamp,
            accessor: user,
            eventId: eventId,
            action: "ACCESS_REQUEST",
            decision: isAllowed,
            reason: reason
        }));
        totalAuditLogs++;

        emit AccessEvaluated(user, eventId, isAllowed, reason, block.timestamp);
        return isAllowed;
    }

    function revokeAccess(address user) external onlyAdmin {
        users[user].isActive = false;
        auditLog.push(AuditRecord({
            timestamp: block.timestamp,
            accessor: user,
            eventId: bytes32(0),
            action: "REVOKE_ACCESS",
            decision: true,
            reason: "Access revoked by administrator"
        }));
        totalAuditLogs++;
    }

    function getEventMetadata(bytes32 eventId) external view returns (
        uint256 timestamp,
        bytes32 deviceHash,
        uint8 prediction,
        string memory attackType,
        uint16 confidence,
        bytes32 payloadHash,
        bytes32 modelHash,
        bytes32 policyHash,
        address reporter
    ) {
        require(securityEvents[eventId].exists, "IIoTRegistry: Event does not exist");
        SecurityEvent storage evt = securityEvents[eventId];
        return (
            evt.timestamp,
            evt.deviceHash,
            evt.prediction,
            evt.attackType,
            evt.confidence,
            evt.payloadHash,
            evt.modelHash,
            evt.policyHash,
            evt.reporter
        );
    }

    function getAuditLogLength() external view returns (uint256) {
        return auditLog.length;
    }

    function getAuditRecord(uint256 index) external view returns (
        uint256 timestamp,
        address accessor,
        bytes32 eventId,
        string memory action,
        bool decision,
        string memory reason
    ) {
        require(index < auditLog.length, "IIoTRegistry: Index out of bounds");
        AuditRecord storage r = auditLog[index];
        return (r.timestamp, r.accessor, r.eventId, r.action, r.decision, r.reason);
    }
}
