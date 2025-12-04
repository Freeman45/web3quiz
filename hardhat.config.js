import '@nomicfoundation/hardhat-toolbox';
import dotenv from 'dotenv';
dotenv.config();

export default {
  solidity: '0.8.19',
  networks: {
    sepolia: {
      url: process.env.RPC_PROVIDER,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    hardhat: {}
  },
  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts'
  }
};