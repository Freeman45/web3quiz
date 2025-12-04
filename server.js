// url= (local file)
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import { createInstance, SepoliaConfig } from '@zama-fhe/relayer-sdk';
import { initDb } from './db.js';
import jwt from 'jsonwebtoken';
import { ethers } from 'ethers';
import fs from 'fs/promises';
import path from 'path';

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use('/static', express.static(path.resolve('static')));
app.use('/', express.static(path.resolve('public')));

const JWT_SECRET = process.env.JWT_SECRET || 'replace-this-secret';
const PORT = process.env.PORT || 3000;

let db;
(async () => {
  db = await initDb();
})().catch((e) => {
  console.error('DB init failed', e);
  process.exit(1);
});

// Initialize Zama Relayer SDK instance (server-side)
// NOTE: This uses SepoliaConfig as an example. Replace or set environment-specific config as needed.
let zamaInstance = null;
(async function initZama() {
  try {
    // This will try to create the relayer SDK instance.
    zamaInstance = await createInstance(SepoliaConfig);
    console.log('Zama relayer SDK initialized (SepoliaConfig).');
  } catch (err) {
    console.warn('Failed to initialize Zama relayer SDK. Continue in degraded mode. Error:', err.message || err);
    zamaInstance = null;
  }
})();

// Helper: generate random nonce
function genNonce() {
  return Math.floor(Math.random() * 1e9).toString();
}

// Wallet-auth endpoints (nonce-sign flow)
app.get('/api/auth/nonce/:wallet', async (req, res) => {
  const wallet = (req.params.wallet || '').toLowerCase();
  if (!ethers.isAddress(wallet)) return res.status(400).json({ error: 'invalid wallet' });

  // upsert user with nonce
  const nonce = genNonce();
  const exists = await db.get('SELECT * FROM users WHERE wallet = ?', wallet);
  if (exists) {
    await db.run('UPDATE users SET nonce = ? WHERE wallet = ?', nonce, wallet);
  } else {
    await db.run('INSERT INTO users (wallet, nonce) VALUES (?, ?)', wallet, nonce);
  }
  res.json({ wallet, nonce });
});

// Verify signature and issue JWT
app.post('/api/auth/login', async (req, res) => {
  const { wallet, signature } = req.body || {};
  if (!wallet || !signature) return res.status(400).json({ error: 'wallet and signature required' });

  const user = await db.get('SELECT * FROM users WHERE wallet = ?', wallet.toLowerCase());
  if (!user) return res.status(400).json({ error: 'request nonce first' });

  const message = `web3quiz-zone: nonce=${user.nonce}`;
  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== wallet.toLowerCase()) {
      return res.status(401).json({ error: 'signature mismatch' });
    }

    // rotate nonce
    const newNonce = genNonce();
    await db.run('UPDATE users SET nonce = ? WHERE wallet = ?', newNonce, wallet.toLowerCase());

    const token = jwt.sign({ wallet: wallet.toLowerCase() }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token });
  } catch (err) {
    res.status(400).json({ error: 'invalid signature' });
  }
});

// auth middleware
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'missing auth' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'bad auth header' });
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.wallet = payload.wallet;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// Create campaign (only authenticated project owner)
app.post('/api/campaigns', requireAuth, async (req, res) => {
  const { title, color, prizePool, questions, prizePoolContract } = req.body || {};
  if (!title || !questions || !Array.isArray(questions)) return res.status(400).json({ error: 'invalid payload' });

  const qjson = JSON.stringify(questions);
  const owner = req.wallet.toLowerCase();
  const result = await db.run(
    'INSERT INTO campaigns (title, color, prize_pool, questions_json, owner_wallet, prize_pool_contract) VALUES (?, ?, ?, ?, ?, ?)',
    title,
    color || '#4CAF50',
    Number(prizePool || 0),
    qjson,
    owner,
    prizePoolContract || process.env.PRIZE_POOL_CONTRACT || null,
  );
  const id = result.lastID;
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', id);
  res.status(201).json(campaign);
});

// List campaigns (public)
app.get('/api/campaigns', async (req, res) => {
  const rows = await db.all('SELECT * FROM campaigns ORDER BY created_at DESC');
  // parse questions JSON
  const campaigns = rows.map((r) => ({ ...r, questions: JSON.parse(r.questions_json) }));
  res.json(campaigns);
});

// Get campaign by id (public)
app.get('/api/campaigns/:id', async (req, res) => {
  const c = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!c) return res.status(404).json({ error: 'not found' });
  c.questions = JSON.parse(c.questions_json);
  res.json(c);
});

/*
  ENCRYPTION FLOW

  Client:
    - Will encrypt answers client-side using Zama relayer SDK (or browser-compatible helper)
    - Client sends encryptedInput (handles) and inputProof to this endpoint

  Server:
    - Verifies the encrypted input using the Zama relayer SDK (server-side instance)
    - If verified, stores participant row and marks pass/fail based on server-side evaluation policy
    - NOTE: The exact relayer-sdk verification method names depend on the SDK version.
      Below we attempt to call a generic verifyInput API on the instance. If your SDK exposes
      different methods, replace the call accordingly.
*/

app.post('/api/campaigns/:id/join', async (req, res) => {
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!campaign) return res.status(404).json({ error: 'campaign not found' });

  const { participant, encryptedInput, inputProof } = req.body || {};
  if (!participant || !encryptedInput || !inputProof) {
    return res.status(400).json({ error: 'participant, encryptedInput and inputProof required' });
  }

  // Verify encrypted input using Zama relayer SDK
  if (!zamaInstance) {
    return res.status(500).json({ error: 'Zama relayer SDK not initialized on server' });
  }

  try {
    // Example verification call.
    // IMPORTANT: Replace the method below with the correct one from the version of @zama-fhe/relayer-sdk you use.
    // The SDK typically exposes a verification / relayer client which can verify inputs with:
    //   await zamaInstance.verifyEncryptedInput({ contractAddress, externalInput, proof })
    // or similar.
    //
    // We provide a best-effort placeholder call below. If your SDK exposes a different API,
    // adjust accordingly.
    const contractAddress = campaign.prize_pool_contract || process.env.PRIZE_POOL_CONTRACT;
    if (!contractAddress) {
      return res.status(500).json({ error: 'prize pool contract not configured for this campaign' });
    }

    // Placeholder: perform verification. Replace with actual SDK call:
    let verificationPassed = false;
    try {
      if (typeof zamaInstance.verifyEncryptedInput === 'function') {
        // preferred SDK method if present
        verificationPassed = await zamaInstance.verifyEncryptedInput({
          contractAddress,
          externalInput: JSON.parse(encryptedInput),
          proof: inputProof,
        });
      } else if (typeof zamaInstance.verifyInput === 'function') {
        verificationPassed = await zamaInstance.verifyInput(contractAddress, JSON.parse(encryptedInput), inputProof);
      } else if (typeof zamaInstance.relayer === 'object' && typeof zamaInstance.relayer.verify === 'function') {
        verificationPassed = await zamaInstance.relayer.verify(contractAddress, JSON.parse(encryptedInput), inputProof);
      } else {
        // If the SDK doesn't provide a JS verification helper in your version,
        // you might need to call the Gateway contract or a relayer HTTP endpoint.
        throw new Error('no verify method found on zamaInstance - check SDK docs for correct method');
      }
    } catch (innerErr) {
      console.error('Relayer SDK verification error (inner):', innerErr);
      throw innerErr;
    }

    if (!verificationPassed) {
      return res.status(400).json({ error: 'encrypted input verification failed' });
    }

    // At this point the encrypted input is verified.
    // We still need to evaluate whether the participant passed the quiz.
    // For fully confidential flow, scoring can be done via FHE on-chain or by Coprocessors.
    // For demonstration we'll capture the encrypted input + proof and mark as "pending" for admin review.
    // Optionally, if your project publishes a plaintext answer-check on server side, decrypt here (requires decryption permissions).

    const insert = await db.run(
      'INSERT INTO participants (campaign_id, wallet, encrypted_input, input_proof, score, passed) VALUES (?, ?, ?, ?, ?, ?)',
      campaign.id,
      participant.toLowerCase(),
      encryptedInput,
      inputProof,
      null,
      0,
    );

    res.json({ ok: true, participantId: insert.lastID, verificationPassed: true, pending: true });
  } catch (err) {
    console.error('verification error:', err);
    res.status(500).json({ error: 'verification error: ' + (err.message || err) });
  }
});

/*
  Admin endpoints:

  - List participants for a campaign (campaign owner only)
  - Admin can run decryption/score (using the Zama SDK or manual review)
  - Admin can request payout which calls the PrizePool.payWinner using server signer (owner)
*/

// list participants (owner-only)
app.get('/api/campaigns/:id/participants', requireAuth, async (req, res) => {
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!campaign) return res.status(404).json({ error: 'campaign not found' });
  if (campaign.owner_wallet.toLowerCase() !== req.wallet.toLowerCase()) return res.status(403).json({ error: 'not owner' });

  const rows = await db.all('SELECT * FROM participants WHERE campaign_id = ? ORDER BY created_at DESC', req.params.id);
  res.json(rows);
});

// admin: run decryption + scoring for a participant using Zama SDK (example)
app.post('/api/participants/:id/decrypt-score', requireAuth, async (req, res) => {
  const pid = req.params.id;
  const p = await db.get('SELECT * FROM participants WHERE id = ?', pid);
  if (!p) return res.status(404).json({ error: 'participant not found' });

  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', p.campaign_id);
  if (!campaign) return res.status(404).json({ error: 'campaign not found' });
  if (campaign.owner_wallet.toLowerCase() !== req.wallet.toLowerCase()) return res.status(403).json({ error: 'not owner' });

  if (!zamaInstance) return res.status(500).json({ error: 'Zama SDK not initialized' });

  try {
    // Example: use the SDK to request decryption of the result (requires that the contract allowed decryption)
    // The method below is a placeholder and needs to be replaced by the SDK's actual decryption API.
    // e.g. await zamaInstance.requestDecryption({ contractAddress, ciphertext });
    let clearAnswers = null;
    try {
      if (typeof zamaInstance.requestDecryption === 'function') {
        const resDec = await zamaInstance.requestDecryption({
          contractAddress: campaign.prize_pool_contract,
          ciphertext: JSON.parse(p.encrypted_input),
          requesterAddress: req.wallet,
        });
        // resDec should contain the decrypted payload; adjust according to SDK
        clearAnswers = resDec?.cleartext ?? null;
      } else {
        throw new Error('no requestDecryption method on zamaInstance - check SDK docs');
      }
    } catch (inner) {
      throw inner;
    }

    // If decryption succeeded and we have clearAnswers (array of answers),
    // perform scoring against the stored questions.
    let score = 0;
    if (Array.isArray(clearAnswers)) {
      const questions = JSON.parse(campaign.questions_json);
      for (let i = 0; i < questions.length; i++) {
        const correct = (questions[i].a || '').toString().trim().toLowerCase();
        const given = (clearAnswers[i] || '').toString().trim().toLowerCase();
        if (correct && given && correct === given) score++;
      }
    } else {
      // If decryption didn't return a structured array, admin must review manually
      return res.status(500).json({ error: 'decryption returned unexpected payload; manual review required' });
    }

    const passed = score >= Math.ceil(JSON.parse(campaign.questions_json).length * 0.7) ? 1 : 0;
    await db.run('UPDATE participants SET score = ?, passed = ? WHERE id = ?', score, passed, pid);

    res.json({ participantId: pid, score, passed });
  } catch (err) {
    console.error('decrypt-score error', err);
    res.status(500).json({ error: 'decrypt-score error: ' + (err.message || err) });
  }
});

// admin payout endpoint: uses server signer (configured via PRIVATE_KEY) to call the PrizePool contract
app.post('/api/campaigns/:id/payout', requireAuth, async (req, res) => {
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!campaign) return res.status(404).json({ error: 'campaign not found' });
  if (campaign.owner_wallet.toLowerCase() !== req.wallet.toLowerCase()) return res.status(403).json({ error: 'not owner' });

  const { participantId, amountEth } = req.body || {};
  if (!participantId || !amountEth) return res.status(400).json({ error: 'participantId and amountEth required' });

  const participant = await db.get('SELECT * FROM participants WHERE id = ? AND campaign_id = ?', participantId, campaign.id);
  if (!participant) return res.status(404).json({ error: 'participant not found' });

  // Only payout participants who passed (or admin can override)
  if (participant.passed !== 1) {
    return res.status(400).json({ error: 'participant did not pass or not yet approved' });
  }

  const PRIZE_POOL_CONTRACT = campaign.prize_pool_contract || process.env.PRIZE_POOL_CONTRACT;
  if (!PRIZE_POOL_CONTRACT) return res.status(500).json({ error: 'prize pool contract not configured' });

  // server signer
  const providerUrl = process.env.RPC_PROVIDER || SepoliaConfig.network || 'https://eth-sepolia.public.blastapi.io';
  const provider = new ethers.JsonRpcProvider(providerUrl);
  const pk = process.env.PRIVATE_KEY;
  if (!pk) return res.status(500).json({ error: 'server PRIVATE_KEY not set in env to execute payouts' });
  const wallet = new ethers.Wallet(pk, provider);

  // Minimal ABI for PrizePool.payWinner
  const prizePoolAbi = [
    'function payWinner(address payable to, uint256 amount) external',
    'function balance() view returns (uint256)',
  ];
  const prizePool = new ethers.Contract(PRIZE_POOL_CONTRACT, prizePoolAbi, wallet);

  try {
    const valueWei = ethers.parseEther(amountEth.toString());
    const tx = await prizePool.payWinner(participant.wallet, valueWei);
    await tx.wait();
    res.json({ ok: true, txHash: tx.hash });
  } catch (err) {
    console.error('payout error', err);
    res.status(500).json({ error: 'payout failed: ' + (err.message || err) });
  }
});

app.listen(PORT, () => {
  console.log(`web3quiz-zone secure backend running on http://localhost:${PORT}`);
});