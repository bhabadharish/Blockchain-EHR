const EHRAccessControl = artifacts.require("EHRAccessControl");
const EHRIntegrityRegistry = artifacts.require("EHRIntegrityRegistry");

module.exports = async function (deployer, network, accounts) {
  // 1. Deploy Access Control Contract
  await deployer.deploy(EHRAccessControl);
  const accessControl = await EHRAccessControl.deployed();

  // 2. Deploy Integrity Registry with Access Control Reference
  await deployer.deploy(EHRIntegrityRegistry, accessControl.address);
  const integrityRegistry = await EHRIntegrityRegistry.deployed();

  console.log("EHRAccessControl deployed at:", accessControl.address);
  console.log("EHRIntegrityRegistry deployed at:", integrityRegistry.address);
};
