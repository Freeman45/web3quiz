import { ethers } from 'hardhat';
import dotenv from 'dotenv';
dotenv.config();

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log('Deploying with', deployer.address);

  const PrizePool = await ethers.getContractFactory('PrizePool');
  const pool = await PrizePool.deploy(deployer.address);
  await pool.deployed();

  console.log('PrizePool deployed to:', pool.address);
  console.log('Set PRIZE_POOL_CONTRACT in your .env or create campaigns with this address.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});