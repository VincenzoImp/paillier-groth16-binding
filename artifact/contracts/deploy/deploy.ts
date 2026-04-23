import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  const useRealVerifier = process.env.REAL_VERIFIER !== "false";

  let membershipVerifierAddress: string;

  if (useRealVerifier) {
    const realVerifier = await ethers.deployContract("Groth16Verifier");
    await realVerifier.waitForDeployment();
    membershipVerifierAddress = await realVerifier.getAddress();
    console.log("Deployed REAL Groth16Verifier");
  } else {
    const mockVerifier = await ethers.deployContract("MockVerifier");
    await mockVerifier.waitForDeployment();
    membershipVerifierAddress = await mockVerifier.getAddress();
    console.log("Deployed MockVerifier (set REAL_VERIFIER=true for production)");
  }

  const ballotValidityVerifier = await ethers.deployContract("MockBallotValidityVerifier");
  await ballotValidityVerifier.waitForDeployment();

  const ballotBox = await ethers.deployContract("CrossGroupBallotBox", [
    membershipVerifierAddress,
    await ballotValidityVerifier.getAddress(),
    deployer.address,
  ]);
  await ballotBox.waitForDeployment();

  console.log(
    JSON.stringify(
      {
        deployer: deployer.address,
        membershipVerifier: membershipVerifierAddress,
        ballotValidityVerifier: await ballotValidityVerifier.getAddress(),
        ballotBox: await ballotBox.getAddress(),
        realVerifier: useRealVerifier,
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
