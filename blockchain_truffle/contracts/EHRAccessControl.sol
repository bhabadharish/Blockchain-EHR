// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EHRAccessControl
 * @dev Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) for EHR Systems.
 * Implements strict role verification for ADMIN, DOCTOR, NURSE, RESEARCHER, AUDITOR, PATIENT, and SECURITY_ANALYST.
 */
contract EHRAccessControl {
    address public admin;

    struct UserProfile {
        string role;
        bool isActive;
        uint256 registeredAt;
        uint256 expirationTime; // 0 for permanent
        mapping(string => string) attributes;
    }

    mapping(address => UserProfile) private users;

    // Events
    event UserRegistered(address indexed user, string role, uint256 expirationTime);
    event AccessRevoked(address indexed user, string reason);
    event AttributeSet(address indexed user, string key, string value);
    event AccessChecked(address indexed caller, string requiredRole, bool granted, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not authorized ADMIN");
        _;
    }

    constructor() {
        admin = msg.sender;
        UserProfile storage profile = users[admin];
        profile.role = "ADMIN";
        profile.isActive = true;
        profile.registeredAt = block.timestamp;
        profile.expirationTime = 0;
        emit UserRegistered(admin, "ADMIN", 0);
    }

    function registerUser(
        address user,
        string memory role,
        uint256 durationSeconds
    ) public onlyAdmin {
        require(user != address(0), "Invalid user address");
        UserProfile storage profile = users[user];
        profile.role = role;
        profile.isActive = true;
        profile.registeredAt = block.timestamp;
        profile.expirationTime = durationSeconds > 0 ? block.timestamp + durationSeconds : 0;
        emit UserRegistered(user, role, profile.expirationTime);
    }

    function revokeUser(address user, string memory reason) public onlyAdmin {
        require(users[user].isActive, "User is already inactive or not found");
        users[user].isActive = false;
        emit AccessRevoked(user, reason);
    }

    function setUserAttribute(
        address user,
        string memory key,
        string memory value
    ) public onlyAdmin {
        require(users[user].isActive, "User is not active");
        users[user].attributes[key] = value;
        emit AttributeSet(user, key, value);
    }

    function isAuthorized(address caller, string memory requiredRole) public returns (bool, string memory) {
        UserProfile storage profile = users[caller];
        if (!profile.isActive) {
            emit AccessChecked(caller, requiredRole, false, "USER_INACTIVE_OR_REVOKED");
            return (false, "USER_INACTIVE_OR_REVOKED");
        }
        if (profile.expirationTime > 0 && block.timestamp > profile.expirationTime) {
            emit AccessChecked(caller, requiredRole, false, "CREDENTIAL_EXPIRED");
            return (false, "CREDENTIAL_EXPIRED");
        }
        if (keccak256(bytes(profile.role)) == keccak256(bytes("ADMIN"))) {
            emit AccessChecked(caller, requiredRole, true, "ADMIN_ACCESS_GRANTED");
            return (true, "ADMIN_ACCESS_GRANTED");
        }
        if (keccak256(bytes(profile.role)) == keccak256(bytes(requiredRole))) {
            emit AccessChecked(caller, requiredRole, true, "ROLE_AUTHORIZED");
            return (true, "ROLE_AUTHORIZED");
        }
        emit AccessChecked(caller, requiredRole, false, "ROLE_MISMATCH_DENIED");
        return (false, "ROLE_MISMATCH_DENIED");
    }

    function getUserRole(address user) public view returns (string memory, bool, uint256) {
        return (users[user].role, users[user].isActive, users[user].expirationTime);
    }
}
