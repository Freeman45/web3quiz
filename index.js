import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import jwt from 'jsonwebtoken';
import { ethers } from 'ethers';
import { initDb } from './db.js';
import { initRelayer, verifyEncryptedInput, requestDecryption } from './relayer.js';

dotenv.config();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(process.cwd(), 'client', 'dist')));
app.use('/static', express.static(path.join(process.cwd(), 'client', 'public')));

let db;
(async () => {
  db = await initDb();
  // init relayer in background
  await initRelayer();
})().catch((e) => {
  console.error('Startup DB/Relayer error', e);
  process.exit(1);
});

// helper: generate nonce
function genNonce() {
  return Math.floor(Math.random() * 1e9).toString();
}

// wallet-auth
app.get('/api/auth/nonce/:wallet', async (req, res) => {
  const wallet = (req.params.wallet || '').toLowerCase();
  if (!ethers.isAddress(wallet)) return res.status(400).json({ error: 'invalid wallet' });
  const nonce = genNonce();
  const existing = await db.get('SELECT * FROM users WHERE wallet = ?', wallet);
  if (existing) {
    await db.run('UPDATE users SET nonce = ? WHERE wallet = ?', nonce, wallet);
  } else {
    await db.run('INSERT INTO users (wallet, nonce) VALUES (?, ?)', wallet, nonce);
  }
  res.json({ wallet, nonce });
});

app.post('/api/auth/login', async (req, res) => {
  const { wallet, signature } = req.body || {};
  if (!wallet || !signature) return res.status(400).json({ error: 'missing' });
  const user = await db.get('SELECT * FROM users WHERE wallet = ?', wallet.toLowerCase());
  if (!user) return res.status(400).json({ error: 'nonce required' });
  const message = `web3quiz-zone: nonce=${user.nonce}`;
  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== wallet.toLowerCase()) return res.status(401).json({ error: 'invalid signature' });

    // rotate nonce
    const newNonce = genNonce();
    await db.run('UPDATE users SET nonce = ? WHERE wallet = ?', newNonce, wallet.toLowerCase());

    const token = jwt.sign({ wallet: wallet.toLowerCase() }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token });
  } catch (err) {
    return res.status(400).json({ error: 'verification failed' });
  }
});

function requireAuth(req, res, next) {
  const a = req.headers.authorization;
  if (!a) return res.status(401).json({ error: 'missing auth' });
  const parts = a.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'bad auth header' });
  try {
    const p = jwt.verify(parts[1], JWT_SECRET);
    req.wallet = p.wallet;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// campaigns
app.post('/api/campaigns', requireAuth, async (req, res) => {
  const { title, color, prizePool, questions, prizePoolContract } = req.body || {};
  if (!title || !questions || !Array.isArray(questions)) return res.status(400).json({ error: 'invalid' });
  const qjson = JSON.stringify(questions);
  const owner = req.wallet.toLowerCase();
  const result = await db.run(
    'INSERT INTO campaigns (title, color, prize_pool, questions_json, owner_wallet, prize_pool_contract) VALUES (?, ?, ?, ?, ?, ?)',
    title, color || '#4CAF50', Number(prizePool || 0), qjson, owner, prizePoolContract || process.env.PRIZE_POOL_CONTRACT || null
  );
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', result.lastID);
  res.status(201).json({ campaign });
});

app.get('/api/campaigns', async (req, res) => {
  const rows = await db.all('SELECT * FROM campaigns ORDER BY created_at DESC');
  const mapped = rows.map(r => ({ ...r, questions: JSON.parse(r.questions_json) }));
  res.json(mapped);
});

app.get('/api/campaigns/:id', async (req, res) => {
  const c = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!c) return res.status(404).json({ error: 'not found' });
  c.questions = JSON.parse(c.questions_json);
  res.json(c);
});

// join: participant submits encrypted input + proof
app.post('/api/campaigns/:id/join', async (req, res) => {
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!campaign) return res.status(404).json({ error: 'no campaign' });

  const { participant, encryptedInput, inputProof } = req.body || {};
  if (!participant || !encryptedInput || !inputProof) return res.status(400).json({ error: 'missing' });

  // ensure wallet format
  if (!ethers.isAddress(participant)) return res.status(400).json({ error: 'invalid participant address' });

  // verify using relayer
  try {
    // parse encryptedInput if JSON string
    const externalInput = typeof encryptedInput === 'string' ? JSON.parse(encryptedInput) : encryptedInput;
    const contractAddress = campaign.prize_pool_contract || process.env.PRIZE_POOL_CONTRACT;
    if (!contractAddress) return res.status(500).json({ error: 'no prize pool contract configured' });

    const ok = await verifyEncryptedInput(contractAddress, externalInput, inputProof);
    if (!ok) return res.status(400).json({ error: 'verification failed' });

    // store participant as pending; scoring/decryption handled by owner/admin later
    const r = await db.run(
      'INSERT INTO participants (campaign_id, wallet, encrypted_input, input_proof) VALUES (?, ?, ?, ?)',
      campaign.id, participant.toLowerCase(), JSON.stringify(externalInput), inputProof
    );
    res.json({ ok: true, participantId: r.lastID });
  } catch (err) {
    console.error('join error', err);
    res.status(500).json({ error: 'verification or storage error: ' + (err.message || err) });
  }
});

// owner-only: list participants
app.get('/api/campaigns/:id/participants', requireAuth, async (req, res) => {
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!campaign) return res.status(404).json({ error: 'no campaign' });
  if (campaign.owner_wallet.toLowerCase() !== req.wallet.toLowerCase()) return res.status(403).json({ error: 'not owner' });

  const parts = await db.all('SELECT * FROM participants WHERE campaign_id = ? ORDER BY created_at DESC', campaign.id);
  res.json(parts);
});

// owner-only: request decryption & score a participant
app.post('/api/participants/:id/decrypt-score', requireAuth, async (req, res) => {
  const pid = req.params.id;
  const p = await db.get('SELECT * FROM participants WHERE id = ?', pid);
  if (!p) return res.status(404).json({ error: 'participant not found' });

  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', p.campaign_id);
  if (!campaign) return res.status(404).json({ error: 'campaign not found' });
  if (campaign.owner_wallet.toLowerCase() !== req.wallet.toLowerCase()) return res.status(403).json({ error: 'not owner' });

  try {
    const ciphertext = JSON.parse(p.encrypted_input);
    const decRes = await requestDecryption(campaign.prize_pool_contract, ciphertext, req.wallet);
    // decRes should contain cleartext answers - SDK-dependent shape
    // We'll expect decRes.cleartext as an array of strings; adapt if needed
    const clear = decRes?.cleartext ?? decRes?.plain ?? null;
    if (!Array.isArray(clear)) {
      return res.status(500).json({ error: 'decryption returned unexpected payload; manual review required', decRes });
    }

    // scoring
    const questions = JSON.parse(campaign.questions_json);
    let score = 0;
    for (let i = 0; i < questions.length; i++) {
      const corr = (questions[i].a || '').toString().trim().toLowerCase();
      const got = (clear[i] || '').toString().trim().toLowerCase();
      if (corr && got && corr === got) score++;
    }
    const passed = score >= Math.ceil(questions.length * 0.7) ? 1 : 0;
    await db.run('UPDATE participants SET score = ?, passed = ? WHERE id = ?', score, passed, pid);

    res.json({ ok: true, participantId: pid, score, passed });
  } catch (err) {
    console.error('decrypt-score error', err);
    res.status(500).json({ error: 'decrypt/score failed: ' + (err.message || err) });
  }
});

// owner-only: payout
app.post('/api/campaigns/:id/payout', requireAuth, async (req, res) => {
  const campaign = await db.get('SELECT * FROM campaigns WHERE id = ?', req.params.id);
  if (!campaign) return res.status(404).json({ error: 'campaign not found' });
  if (campaign.owner_wallet.toLowerCase() !== req.wallet.toLowerCase()) return res.status(403).json({ error: 'not owner' });

  const { participantId, amountEth } = req.body || {};
  if (!participantId || !amountEth) return res.status(400).json({ error: 'participantId and amountEth required' });

  const p = await db.get('SELECT * FROM participants WHERE id = ? AND campaign_id = ?', participantId, campaign.id);
  if (!p) return res.status(404).json({ error: 'participant not found' });
  if (p.passed !== 1) return res.status(400).json({ error: 'participant not approved / did not pass' });

  const PRIZE_POOL_CONTRACT = campaign.prize_pool_contract || process.env.PRIZE_POOL_CONTRACT;
  if (!PRIZE_POOL_CONTRACT) return res.status(500).json({ error: 'no prize pool contract configured' });

  const providerUrl = process.env.RPC_PROVIDER;
  if (!providerUrl) return res.status(500).json({ error: 'RPC_PROVIDER not configured' });

  const pk = process.env.PRIVATE_KEY;
  if (!pk) return res.status(500).json({ error: 'server PRIVATE_KEY not configured' });

  try {
    const provider = new ethers.JsonRpcProvider(providerUrl);
    const wallet = new ethers.Wallet(pk, provider);
    const prizePoolAbi = [
      'function payWinner(address payable to, uint256 amount) external',
      'function balance() view returns (uint256)'
    ];
    const pool = new ethers.Contract(PRIZE_POOL_CONTRACT, prizePoolAbi, wallet);
    const value = ethers.parseEther(amountEth.toString());

    const tx = await pool.payWinner(p.wallet, value);
    await tx.wait();

    res.json({ ok: true, txHash: tx.hash });
  } catch (err) {
    console.error('payout error', err);
    res.status(500).json({ error: 'payout failed: ' + (err.message || err) });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});