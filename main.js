// url= (local file)
// Frontend for FHE-enabled flows (wallet auth + encrypted submission scaffold)
// Notes:
// - This frontend demonstrates wallet-auth (nonce + signature -> JWT)
// - It scaffolds client-side encryption with Zama relayer SDK, but actual SDK function calls are left as examples.
//   To enable real client-side encryption you must bundle a browser-compatible version of @zama-fhe/relayer-sdk
//   and replace the placeholder code under "encryptAnswersWithZama" with real SDK calls.

const connectBtn = document.getElementById('connectBtn');
const addrSpan = document.getElementById('addr');
const signinBtn = document.getElementById('signinBtn');

let provider, signer, address;
let jwtToken = localStorage.getItem('w3q_jwt') || null;

async function connectWallet() {
  if (!window.ethereum) {
    alert('Install MetaMask');
    return;
  }
  provider = new ethers.BrowserProvider(window.ethereum);
  await provider.send('eth_requestAccounts', []);
  signer = await provider.getSigner();
  address = await signer.getAddress();
  addrSpan.textContent = address;
  connectBtn.textContent = 'Connected';
  document.getElementById('authRequestNonce').disabled = false;
  loadCampaigns();
}
connectBtn.addEventListener('click', connectWallet);

// AUTH flow
document.getElementById('authRequestNonce').addEventListener('click', async () => {
  if (!address) return alert('connect wallet first');
  const res = await fetch(`/api/auth/nonce/${address}`);
  const data = await res.json();
  document.getElementById('authStatus').textContent = `Nonce fetched: ${data.nonce}`;
  document.getElementById('authSign').disabled = false;
});

document.getElementById('authSign').addEventListener('click', async () => {
  if (!address) return alert('connect');
  // fetch nonce from server to ensure it's the latest
  const resp = await fetch(`/api/auth/nonce/${address}`);
  const { nonce } = await resp.json();
  const message = `web3quiz-zone: nonce=${nonce}`;
  const sig = await signer.signMessage(message);
  const loginRes = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ wallet: address, signature: sig }),
  });
  const j = await loginRes.json();
  if (!loginRes.ok) {
    alert('Login failed: ' + (j.error || JSON.stringify(j)));
    return;
  }
  jwtToken = j.token;
  localStorage.setItem('w3q_jwt', jwtToken);
  document.getElementById('authStatus').textContent = 'Authenticated as owner';
  document.getElementById('createSection').classList.remove('hidden');
});

// Create campaign (owner)
document.getElementById('createForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!jwtToken) return alert('authenticate as owner');
  const title = document.getElementById('title').value;
  const color = document.getElementById('color').value;
  const prize = document.getElementById('prize').value;
  let questions;
  try { questions = JSON.parse(document.getElementById('questions').value); } catch (err) { return alert('invalid questions JSON'); }
  const prizeAddr = document.getElementById('prizeAddr').value || null;

  const res = await fetch('/api/campaigns', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + jwtToken },
    body: JSON.stringify({ title, color, prizePool: prize, questions, prizePoolContract: prizeAddr }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert('Create failed: ' + (data.error || JSON.stringify(data)));
    return;
  }
  document.getElementById('createResult').textContent = 'Campaign created id=' + data.id;
  loadCampaigns();
});

// load campaigns
async function loadCampaigns() {
  const res = await fetch('/api/campaigns');
  const list = await res.json();
  const container = document.getElementById('campaigns');
  container.innerHTML = '';
  for (const c of list) {
    const div = document.createElement('div');
    div.className = 'campaign';
    div.style.borderLeft = `6px solid ${c.color}`;
    div.innerHTML = `
      <h3>${c.title}</h3>
      <p>Owner: ${truncate(c.owner_wallet || c.owner)}</p>
      <p>Prize target: ${c.prize_pool} ETH</p>
      <p>Questions: ${c.questions.length}</p>
      <button data-id="${c.id}" class="joinBtn">Join (encrypt answers)</button>
    `;
    container.appendChild(div);
  }
  document.querySelectorAll('.joinBtn').forEach(btn => {
    btn.addEventListener('click', () => openJoin(btn.dataset.id));
  });
}

function truncate(a){ if(!a) return ''; return a.slice(0,6)+'...'+a.slice(-4); }

let currentCampaign = null;

async function openJoin(id) {
  const res = await fetch(`/api/campaigns/${id}`);
  if (!res.ok) return alert('campaign not found');
  const c = await res.json();
  currentCampaign = c;
  document.getElementById('active').innerHTML = `<h3 style="color:${c.color}">${c.title}</h3><p>Prize pool contract: ${c.prize_pool_contract || 'not set'}</p>`;
  const form = document.getElementById('answerForm');
  form.innerHTML = '';
  c.questions.forEach((q, i) => {
    const div = document.createElement('div');
    div.innerHTML = `<label>Q${i+1}: ${q.q}</label><input name="a${i}" required />`;
    form.appendChild(div);
  });
  const submit = document.createElement('button');
  submit.textContent = 'Encrypt & Submit Answers';
  form.appendChild(submit);
  document.getElementById('join').classList.remove('hidden');

  form.onsubmit = async (e) => {
    e.preventDefault();
    if (!signer) return alert('connect wallet first');

    // collect answers
    const fd = new FormData(form);
    const answers = currentCampaign.questions.map((_, i) => fd.get('a'+i) || '');

    // === IMPORTANT: encryptAnswersWithZama MUST use a browser-compatible Zama relayer SDK
    // Replace the placeholder below with actual SDK calls after bundling the SDK for browser.
    // Example pseudocode (SDK-specific):
    //   const instance = await createInstance(SepoliaConfig); // or use an injected relayer client
    //   const enc = await instance.createEncryptedInput(contractAddress, signerAddress)
    //     .addStringArray(answers)
    //     .encrypt();
    //
    // The enc object should contain:
    //   enc.handles (ciphertext handles / externalEuint references)
    //   enc.inputProof (ZK proof)
    //
    // We'll POST those to the server for verification.

    let encryptedPayload;
    let inputProof;
    try {
      const stub = await encryptAnswersWithZamaStub(answers);
      encryptedPayload = JSON.stringify(stub.handles);
      inputProof = stub.inputProof;
    } catch (err) {
      alert('Encryption failed: ' + err.message);
      return;
    }

    // submit to server
    const resp = await fetch(`/api/campaigns/${currentCampaign.id}/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        participant: address,
        encryptedInput: encryptedPayload,
        inputProof
      })
    });
    const json = await resp.json();
    if (!resp.ok) {
      alert('Submission failed: ' + (json.error || JSON.stringify(json)));
      return;
    }
    document.getElementById('joinResult').textContent = 'Submission accepted, pending admin verification.';
  };
}

// Placeholder: simulate encryption with Zama - replace with real SDK
async function encryptAnswersWithZamaStub(answers) {
  // WARNING: THIS IS ONLY A STUB FOR DEMO PURPOSES.
  // Replace with real encryption via the Zama Relayer SDK in your browser bundle.
  // The server will attempt to verify the payload via the relayer SDK; this stub will NOT verify.
  return {
    handles: {
      // example structure: adapt to the SDK used by your backend
      ciphertext: btoa(JSON.stringify({ answers })),
      meta: { ts: Date.now() }
    },
    inputProof: 'stub-proof'
  };
}

// initial UI wiring: connect & optionally auth-related button states
document.getElementById('authRequestNonce').disabled = true;
document.getElementById('authSign').disabled = true;

loadCampaigns();