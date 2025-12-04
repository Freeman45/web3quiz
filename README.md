```markdown
# web3quiz-zone — Full-stack FHE-enabled quiz dApp (starter, improved UI)

This repository provides a complete starter implementation of web3quiz-zone:
- Frontend (Vite) with an improved UI, wallet auth, owner/admin panel, campaign creation UI, and client-side encryption scaffolding for Zama Relayer SDK.
- Backend (Express) with SQLite persistence, wallet nonce-sign JWT auth, Zama relayer-sdk initialization and verification/decryption placeholders, and PrizePool on-chain payout integration.
- Smart contract: contracts/PrizePool.sol (simple escrow for prizes).
- Hardhat scripts to deploy PrizePool to a network (example Sepolia).

Important notes
- Some calls to @zama-fhe/relayer-sdk are SDK-version dependent. This repo includes clear, working scaffolding and fallback checks. After installing the relayer SDK version you plan to use, verify the function names (verifyEncryptedInput, requestDecryption, etc.) against the SDK docs and, if necessary, adjust the few lines in server/relayer.js and client/src/zamaClient.js.
- For security in production: never store private keys plaintext on servers. Use a multisig (Gnosis Safe), remote signer, HSM, or gasless relayer patterns.

Quick start (local)
1. Copy env example:
   cp .env.example .env
   Edit .env: set PRIVATE_KEY (test/private key for dev), RPC_PROVIDER (e.g., Sepolia), JWT_SECRET, PRIZE_POOL_CONTRACT (optional)

2. Install:
   npm install

3. Start dev:
   npm run dev
   - Vite dev server at http://localhost:5173
   - Backend at http://localhost:3000 (proxied by Vite in dev)

4. Deploy PrizePool with Hardhat (optional):
   - Ensure .env has RPC and PRIVATE_KEY funded for testnet
   - npm run deploy:contract
   - Set returned contract address in .env PRIZE_POOL_CONTRACT or in the UI when creating a campaign.

What I implemented
- Authentication: wallet nonce, signature, JWT.
- Persistence: SQLite DB for users, campaigns, participants.
- Admin flows: list participants, request decryption (SDK), score, and payout via PrizePool.payWinner (server signer).
- Client encryption scaffold: example browser-side code shows how to call Zama relayer SDK; if your SDK is browser-ready you can use the provided wrapper (client/src/zamaClient.js) to encrypt and produce a ZKPoK.
- UI improvements: responsive layout, campaign cards, admin dashboard, form validation, better UX messages.

Next steps I can do for you
- Bundle / test with a specific @zama-fhe/relayer-sdk version and update exact SDK calls.
- Replace private-key payouts with Gnosis Safe transaction creation flow (multisig).
- Add unit/integration tests, CI, and Docker deployment files.

If you want me to wire the exact relayer SDK method names for your specific SDK version, tell me the SDK version you plan to use (npm package version or the commit), and I'll update server/client accordingly.
```