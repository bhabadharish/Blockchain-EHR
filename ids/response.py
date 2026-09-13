"""
SOC Response Recommendation Engine & Incident Lifecycle Manager.
Maps detected attack patterns and cryptographic integrity violations to actionable SOC containment workflows.
"""

from typing import Dict, Any, List


class ResponseRecommendationEngine:
    """
    Healthcare Cybersecurity SOC Automated Playbook Recommender.
    Provides clear, prioritized technical countermeasures without executing silent destructive commands.
    """

    PLAYBOOKS = {
        "DDoS_HTTP": [
            "1. Activate upstream Cloudflare/WAF rate-limiting rules on EHR gateway.",
            "2. Enforce connection throttling per client IP on HTTP/REST endpoints.",
            "3. Isolate identified botnet origin CIDR blocks at edge firewall.",
            "4. Monitor clinical database connection pools to prevent thread exhaustion."
        ],
        "DDoS_TCP": [
            "1. Enable SYN cookies on perimeter load balancers.",
            "2. Drop malformed SYN-ACK flood packets matching Edge-IIoT signature.",
            "3. Restrict incoming TCP port 8545/RPC access to authorized hospital nodes only.",
            "4. Verify health of Ganache/Ethereum RPC node listener."
        ],
        "DDoS_UDP": [
            "1. Rate-limit incoming UDP fragments at edge router.",
            "2. Disable DNS/NTP reflection vectors on external interface.",
            "3. Isolate affected telemetry port and verify switch buffer queue depth."
        ],
        "DDoS_ICMP": [
            "1. Filter ICMP Echo Request packets (Ping of Death mitigation) at firewall border.",
            "2. Inspect border gateway bandwidth utilization.",
            "3. Ensure core EHR internal routing remains unaffected."
        ],
        "MITM": [
            "1. Terminate affected transmission session immediately.",
            "2. Trigger automated AES-256-GCM session key rotation via KMS.",
            "3. Validate mutual TLS (mTLS) certificate fingerprints on both transmission endpoints.",
            "4. Inspect ARP tables and internal routing tables for poisoning artifacts.",
            "5. Re-verify SHA-256 integrity of all in-flight payloads against blockchain anchor."
        ],
        "SQL_injection": [
            "1. Block offending source IP at API gateway perimeter.",
            "2. Inspect SQL execution logs for parameterized query bypasses.",
            "3. Validate sanitization rules on patient record query parameters.",
            "4. Preserve web request payload as cryptographic evidence for SOC forensics."
        ],
        "Ransomware": [
            "1. Immediately isolate affected host/storage node from clinical network segment.",
            "2. Revoke all active KMS session keys and lock cryptographic master key.",
            "3. Halt automated synchronization with off-chain EHR file repositories.",
            "4. Retrieve immutable backup snapshots and verify SHA-256 hashes against Ganache ledger."
        ],
        "Backdoor": [
            "1. Sever network connectivity to infected host gateway.",
            "2. Kill unauthorized listening sockets and background processes.",
            "3. Revoke all credentials and smart contract access roles assigned to the node.",
            "4. Perform memory dump and forensics analysis on affected server."
        ],
        "Password": [
            "1. Enforce account lockout with exponential backoff on affected clinician ID.",
            "2. Invalidate current session tokens across all hospital gateways.",
            "3. Require mandatory hardware MFA (FIDO2/WebAuthn) re-authentication.",
            "4. Audit recent access logs for anomalous credential stuffing patterns."
        ],
        "Uploading": [
            "1. Quarantine uploaded file artifact in isolated sandbox.",
            "2. Perform virus and malware signature scans on binary content.",
            "3. Block endpoint from further file uploads pending administrator review."
        ],
        "XSS": [
            "1. Enforce strict Content Security Policy (CSP) headers on clinical dashboard.",
            "2. Audit client-side DOM sanitization libraries.",
            "3. Invalidate clinician browser session cookies."
        ],
        "Vulnerability_scanner": [
            "1. Add scanning origin IP to temporary rate-limit / ban list.",
            "2. Verify that non-production ports (e.g. 8545, debug RPC) are not exposed externally.",
            "3. Update threat intelligence feed with scanning signature."
        ],
        "Port_Scanning": [
            "1. Log reconnaissance telemetry and flag source IP in SIEM.",
            "2. Confirm firewall drop policy for closed ports.",
            "3. Monitor subsequent traffic from flagged IP for exploit attempts."
        ],
        "Fingerprinting": [
            "1. Suppress server version and OS banners in HTTP/TLS headers.",
            "2. Log probe attempt in SIEM audit database.",
            "3. Maintain standard defensive posture."
        ],
        "INTEGRITY_TAMPERING": [
            "1. CRITICAL: Reject tampered ciphertext immediately. Do NOT attempt clinical usage.",
            "2. Fetch canonical EHR payload from immutable off-chain backup repository.",
            "3. Re-verify SHA-256 against Ganache `EHRIntegrityRegistry` contract anchor.",
            "4. Record `IntegrityFailure` event transaction on Ganache blockchain.",
            "5. Initiate forensic investigation into storage/transmission node compromise."
        ],
        "UNAUTHORIZED_ACCESS": [
            "1. Deny access request at `EHRAccessControl` smart-contract gateway.",
            "2. Record security incident transaction on Ganache blockchain ledger.",
            "3. If repeated attempts, revoke user address and notify clinical administrator.",
            "4. Check for compromised or shared credential usage in hospital audit logs."
        ],
        "Normal": [
            "1. All security checks passed. No containment action required.",
            "2. Payload verified intact against on-chain SHA-256 hash anchor.",
            "3. Maintain standard continuous telemetry monitoring."
        ]
    }

    @classmethod
    def get_recommendations(
        cls,
        attack_type: str,
        integrity_failed: bool = False,
        unauthorized_access: bool = False
    ) -> List[str]:
        """
        Returns an ordered list of prioritized SOC action steps.
        """
        actions = []
        if integrity_failed:
            actions.extend(cls.PLAYBOOKS["INTEGRITY_TAMPERING"])
        if unauthorized_access:
            actions.extend(cls.PLAYBOOKS["UNAUTHORIZED_ACCESS"])
        if attack_type in cls.PLAYBOOKS and attack_type not in ["Normal"]:
            actions.extend(cls.PLAYBOOKS[attack_type])
        elif not actions:
            actions = cls.PLAYBOOKS["Normal"]

        # Deduplicate while preserving priority order
        seen = set()
        deduped = []
        for a in actions:
            if a not in seen:
                seen.add(a)
                deduped.append(a)
        return deduped

    @classmethod
    def get_lifecycle_stages(cls) -> List[str]:
        return [
            "DETECTED",
            "ACKNOWLEDGED",
            "INVESTIGATING",
            "CONTAINED",
            "RECOVERED",
            "CLOSED"
        ]
