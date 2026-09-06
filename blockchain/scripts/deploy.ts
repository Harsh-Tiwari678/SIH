import { network } from "hardhat";

const { ethers, networkName } = await network.create();

async function main() {
  const [deployer] = await ethers.getSigners();

  const balance = await ethers.provider.getBalance(deployer.address);
  const chainId = (await ethers.provider.getNetwork()).chainId;

  console.log("Network:  ", networkName);
  console.log("Chain ID: ", chainId);
  console.log("Deployer:", deployer.address);
  console.log("Balance: ", ethers.formatEther(balance), "ETH");

  const anchor = await ethers.deployContract("EvidenceAnchor", [
    deployer.address,
  ]);

  const deployed = await anchor.waitForDeployment();

  const address = await deployed.getAddress();
  const deployTx = deployed.deploymentTransaction();

  console.log("Contract:", address);

  if (deployTx) {
    console.log("Tx hash: ", deployTx.hash);
  }

  console.log("Owner:   ", await deployed.owner());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});