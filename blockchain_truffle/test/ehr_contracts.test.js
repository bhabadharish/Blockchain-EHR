const EHRAccessControl = artifacts.require("EHRAccessControl");
const EHRIntegrityRegistry = artifacts.require("EHRIntegrityRegistry");

contract("EHR Security Contracts Suite", (accounts) => {
  const [admin, doctor, nurse, unauthorized] = accounts;
  let accessControl;
  let integrityRegistry;

  beforeEach(async () => {
    accessControl = await EHRAccessControl.new({ from: admin });
    integrityRegistry = await EHRIntegrityRegistry.new(accessControl.address, { from: admin });
  });

  describe("EHRAccessControl (RBAC & ABAC)", () => {
    it("should deploy with admin as default active ADMIN", async () => {
      const roleData = await accessControl.getUserRole(admin);
      assert.equal(roleData[0], "ADMIN");
      assert.equal(roleData[1], true);
    });

    it("should allow admin to register a DOCTOR and verify authorization", async () => {
      await accessControl.registerUser(doctor, "DOCTOR", 3600, { from: admin });
      const roleData = await accessControl.getUserRole(doctor);
      assert.equal(roleData[0], "DOCTOR");
      assert.equal(roleData[1], true);

      const authRes = await accessControl.isAuthorized.call(doctor, "DOCTOR");
      assert.equal(authRes[0], true);
      assert.equal(authRes[1], "ROLE_AUTHORIZED");
    });

    it("should reject unauthorized user role request", async () => {
      const authRes = await accessControl.isAuthorized.call(unauthorized, "DOCTOR");
      assert.equal(authRes[0], false);
    });

    it("should revoke user and block access", async () => {
      await accessControl.registerUser(nurse, "NURSE", 3600, { from: admin });
      await accessControl.revokeUser(nurse, "COMPROMISED_SESSION", { from: admin });

      const roleData = await accessControl.getUserRole(nurse);
      assert.equal(roleData[1], false); // isActive = false

      const authRes = await accessControl.isAuthorized.call(nurse, "NURSE");
      assert.equal(authRes[0], false);
      assert.equal(authRes[1], "USER_INACTIVE_OR_REVOKED");
    });
  });

  describe("EHRIntegrityRegistry (Metadata & Tamper Evident Auditing)", () => {
    const recordId = "EHR-RECORD-9467";
    const payloadHash = web3.utils.sha3("CANONICAL_ENCRYPTED_EHR_PAYLOAD_TEST");
    const tamperedHash = web3.utils.sha3("TAMPERED_MALICIOUS_EHR_PAYLOAD");

    it("should register EHR metadata on-chain without exposing plaintext", async () => {
      const tx = await integrityRegistry.registerEHR(
        recordId,
        payloadHash,
        "AES-256-GCM",
        "KEY-ALPHA-01",
        "DOCTOR_ONLY",
        { from: doctor }
      );

      assert.equal(tx.logs[0].event, "EHRRegistered");
      const total = await integrityRegistry.getTotalRecords();
      assert.equal(total.toNumber(), 1);

      const meta = await integrityRegistry.getEHRMetadata(recordId);
      const hashVal = meta.payloadHash || meta[0];
      const algoVal = meta.encryptionAlgorithm || meta[3];
      assert.equal(hashVal, payloadHash);
      assert.equal(algoVal, "AES-256-GCM");
    });

    it("should verify authentic payload hash", async () => {
      await integrityRegistry.registerEHR(
        recordId,
        payloadHash,
        "AES-256-GCM",
        "KEY-ALPHA-01",
        "DOCTOR_ONLY",
        { from: doctor }
      );

      const verifyRes = await integrityRegistry.verifyIntegrity.call(recordId, payloadHash);
      assert.equal(verifyRes[0], true);
      assert.equal(verifyRes[1], "INTEGRITY_VERIFIED_AUTHENTIC");
    });

    it("should detect tampering when hash does not match", async () => {
      await integrityRegistry.registerEHR(
        recordId,
        payloadHash,
        "AES-256-GCM",
        "KEY-ALPHA-01",
        "DOCTOR_ONLY",
        { from: doctor }
      );

      const verifyRes = await integrityRegistry.verifyIntegrity.call(recordId, tamperedHash);
      assert.equal(verifyRes[0], false);
      assert.equal(verifyRes[1], "TAMPER_DETECTED_HASH_MISMATCH");
    });

    it("should record security incident and emit BreachDetected", async () => {
      const tx = await integrityRegistry.recordIncident(
        "INC-2026-001",
        recordId,
        "MITM",
        "CRITICAL",
        9942,
        true,
        "ROTATE_KEY_AND_ISOLATE",
        { from: admin }
      );

      assert.equal(tx.logs[0].event, "SecurityIncidentLogged");
      assert.equal(tx.logs[1].event, "BreachDetected");

      const incident = await integrityRegistry.getIncident("INC-2026-001");
      const attType = incident.attackType || incident[1];
      const sev = incident.severity || incident[2];
      const breached = incident.integrityBreached !== undefined ? incident.integrityBreached : incident[5];
      assert.equal(attType, "MITM");
      assert.equal(sev, "CRITICAL");
      assert.equal(breached, true);
    });
  });
});
