// app.js
// Module-based client. Uses Firebase Realtime Database + WebCrypto E2EE (PBKDF2 -> AES-GCM).
// Version: 2.0 - Menu features removed for mobile optimization

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-analytics.js";
import {
  getDatabase, ref, push, set, get, onChildAdded, onChildRemoved, onValue, remove, off
} from "https://www.gstatic.com/firebasejs/9.22.2/firebase-database.js";

/* --------------------- CONFIG --------------------- */
/* Replace firebaseConfig with your project's values if needed */
const firebaseConfig = {
  apiKey: "AIzaSyAbJ1VjQVqMG-AHtdV4lrWW_0uZJ-UGNUs",
  authDomain: "silent-e1320.firebaseapp.com",
  databaseURL: "https://silent-e1320-default-rtdb.firebaseio.com",
  projectId: "silent-e1320",
  storageBucket: "silent-e1320.firebasestorage.app",
  messagingSenderId: "643377091397",
  appId: "1:643377091397:web:198116cc05160954db242c",
  measurementId: "G-RM0MG0SE6T"
};
/* -------------------------------------------------- */

const app = initializeApp(firebaseConfig);
try { getAnalytics(app); } catch(e) { /* ignore analytics in unsupported env */ }
const db = getDatabase(app);

/* -------------------- DOM -------------------- */
const messagesEl = document.getElementById('messages');
const chatEl = document.getElementById('chat');
const textEl = document.getElementById('text');
const sendBtn = document.getElementById('sendBtn');
const clearBtnTop = document.getElementById('clearBtnTop');
const pairModal = document.getElementById('pairModal');
const createPairBtn = document.getElementById('createPair');
const joinPairBtn = document.getElementById('joinPair');
const createBox = document.getElementById('createBox');
const joinBox = document.getElementById('joinBox');
const createInput = document.getElementById('createInput');
const joinInput = document.getElementById('joinInput');
const doCreate = document.getElementById('doCreate');
const doJoin = document.getElementById('doJoin');
const ppStatus = document.getElementById('pp-status');
const forgetBtn = document.getElementById('forgetBtn');

// Modal elements
const clearChatModal = document.getElementById('clearChatModal');
const cancelClearBtn = document.getElementById('cancelClear');
const confirmClearBtn = document.getElementById('confirmClear');
const forgetModal = document.getElementById('forgetModal');
const cancelForgetBtn = document.getElementById('cancelForget');
const confirmForgetBtn = document.getElementById('confirmForget');
const overwriteModal = document.getElementById('overwriteModal');
const cancelOverwriteBtn = document.getElementById('cancelOverwrite');
const confirmOverwriteBtn = document.getElementById('confirmOverwrite');
const errorModal = document.getElementById('errorModal');
const errorText = document.getElementById('errorText');
const closeErrorBtn = document.getElementById('closeError');
const shareModal = document.getElementById('shareModal');
const shareLinkInput = document.getElementById('shareLinkInput');
const copyLinkBtn = document.getElementById('copyLinkBtn');
const shareWhatsAppBtn = document.getElementById('shareWhatsAppBtn');
const closeShareBtn = document.getElementById('closeShareBtn');
const encryptionBtn = document.getElementById('encryptionBtn');
const encryptionModal = document.getElementById('encryptionModal');
const encSaltEl = document.getElementById('enc_salt');
const encFingerprintEl = document.getElementById('enc_fingerprint');
const copyFingerprintBtn = document.getElementById('copyFingerprintBtn');
const closeEncryptionBtn = document.getElementById('closeEncryptionBtn');

let pendingOverwrite = null; // { code, saltBytes }

/* -------------------- Local keys/state -------------------- */
const LOCAL_PAIR_KEY = 'peacepage_pair_code_chat_v1';
const CLIENT_ID_KEY = 'peacepage_client_id_v1';
let pairCode = null;
let messagesPath = null;
let attached = false;
let cryptoKeyCache = null; // CryptoKey for AES-GCM
let pairSalt = null; // Uint8Array salt used for PBKDF2

/* -------------------- Modal helpers -------------------- */
function showModal(modalEl) {
  modalEl.setAttribute('aria-hidden', 'false');
  modalEl.style.display = 'flex';
  document.documentElement.classList.add('lock-scroll');
}

function hideModal(modalEl) {
  modalEl.setAttribute('aria-hidden', 'true');
  modalEl.style.display = 'none';
  document.documentElement.classList.remove('lock-scroll');
}

function showError(message) {
  errorText.textContent = message;
  showModal(errorModal);
}

/* -------------------- Helpers -------------------- */
function setStatus(s){
  if (ppStatus) ppStatus.textContent = 'Status: ' + s;
  console.log('[pp]', s);
}
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c])); }
function clientId(){
  let id = localStorage.getItem(CLIENT_ID_KEY);
  if (!id){ id = 'c_' + Math.random().toString(36).slice(2,9); localStorage.setItem(CLIENT_ID_KEY, id); }
  return id;
}
function flash110(){
  const el1 = document.querySelector('.num.n1');
  const el2 = document.querySelector('.num.n2');
  const el3 = document.querySelector('.num.n3');
  [el1,el2,el3].forEach(el=>{ if(!el) return; el.classList.add('pop'); setTimeout(()=>el.classList.remove('pop'), 700); });
}

/* -------------------- WebCrypto utilities -------------------- */
function bufToBase64(b){
  return btoa(String.fromCharCode(...new Uint8Array(b)));
}
function base64ToBuf(s){
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// derive AES-GCM CryptoKey from pairing code + salt
async function deriveKeyFromCode(code, saltBytes){
  // PBKDF2 with SHA-256, 150000 iterations (reasonable for client)
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 150000, hash: 'SHA-256' },
    passKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
  return key;
}

// encrypt plaintext string -> { c: base64, iv: base64 }
async function encryptWithKey(key, plainText){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const pt = enc.encode(plainText);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
  return { c: bufToBase64(cipher), iv: bufToBase64(iv) };
}

// decrypt { c, iv } -> plaintext string (or throw)
async function decryptWithKey(key, cipherBase64, ivBase64){
  const cipherBuf = base64ToBuf(cipherBase64);
  const iv = base64ToBuf(ivBase64);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBuf);
  const dec = new TextDecoder();
  return dec.decode(plain);
}

/* -------------------- Firebase pairing helpers -------------------- */

// pairing stored at /peacepage/pairing/{pairCode} => { code, salt: base64, updatedAt }
async function readRemotePairInfo(code){
  try {
    const snap = await get(ref(db, `peacepage/pairing/${code}`));
    if (!snap.exists()) return null;
    return snap.val();
  } catch(e){ console.warn('readRemotePairInfo', e); return null; }
}

// create pairing node with random salt
async function writeRemotePairInfo(code){
  try {
    // generate 16-byte salt
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltBase64 = bufToBase64(saltBytes);
    await set(ref(db, `peacepage/pairing/${code}`), { code, salt: saltBase64, updatedAt: Date.now() });
    return saltBytes;
  } catch(e){ console.error('writeRemotePairInfo', e); return null; }
}

/* -------------------- Message rendering -------------------- */

function createMessageElement(id, plainText, meta, senderIsMe, isEdited = false){
  const row = document.createElement('div');
  row.className = 'msg-row ' + (senderIsMe ? 'me' : 'them');
  row.id = 'msg-' + id;

  const bubble = document.createElement('div');
  bubble.className = 'bubble ' + (senderIsMe ? 'me' : 'them');

  const pre = document.createElement('pre');
  pre.className = 'msg-pre';
  pre.textContent = plainText || '';
  bubble.appendChild(pre);

  const metaEl = document.createElement('div');
  metaEl.className = 'meta';
  metaEl.innerHTML = meta + (isEdited ? ' <span class="edited-label">(edited)</span>' : '');
  bubble.appendChild(metaEl);

  row.appendChild(bubble);
  return row;
}

/* -------------------- Message attach/detach -------------------- */
function appendPlainMessageDOM(id, text, timestamp, sender, isEdited = false, isNew = false){
  const isMine = sender === clientId();
  const timeStr = timestamp ? new Date(timestamp).toLocaleString() : '';
  const row = createMessageElement(id, text, (isMine ? 'You' : 'Them') + ' · ' + timeStr, isMine, isEdited);
  
  // Store timestamp as data attribute for later reference
  if (timestamp) {
    row.setAttribute('data-timestamp', timestamp);
  }
  
  if (isNew) {
    row.classList.add('just-sent');
  }
  
  messagesEl.appendChild(row);
  while (messagesEl.children.length > 1000) {
    messagesEl.removeChild(messagesEl.firstChild);
  }
  
  // Scroll to bottom smoothly
  setTimeout(() => {
    chatEl.scrollTo({ top: chatEl.scrollHeight, behavior: 'smooth' });
  }, 50);
  
  flash110();
}

/* -------------------- Realtime listeners -------------------- */
function attachListeners(){
  if (!pairCode || attached) return;
  if (!cryptoKeyCache) { setStatus('no crypto key'); return; }
  attached = true;
  messagesPath = `peacepage/messages/${pairCode}`;
  const nodeRef = ref(db, messagesPath);
  messagesEl.innerHTML = '';
  setStatus('listening for messages');

  onChildAdded(nodeRef, async snap => {
    const id = snap.key;
    const d = snap.val();
    if (!d) return;
    // decryption: if `d.c` exists -> encrypted, else raw (backwards compatibility)
    if (d.c && d.iv) {
      try {
        const plain = await decryptWithKey(cryptoKeyCache, d.c, d.iv);
        const isEdited = d.edited === true;
        appendPlainMessageDOM(id, plain, d.t, d.sender, isEdited, d.sender === clientId());
      } catch(e){
        console.warn('decrypt failed', e);
        appendPlainMessageDOM(id, '[Encrypted — cannot decrypt]', d.t, d.sender, false, false);
      }
    } else if (d.text) {
      appendPlainMessageDOM(id, d.text, d.t, d.sender, false, d.sender === clientId());
    }
    setStatus('listening');
  }, err => {
    console.error('onChildAdded error', err);
    setStatus('realtime error');
    showError('Connection error. Please refresh.');
  });

  onChildRemoved(nodeRef, snap => {
    const id = snap.key;
    const el = document.getElementById('msg-' + id);
    if (el) el.remove();
  }, err => {
    console.error('onChildRemoved error', err);
  });

  // Attach typing indicator listener
  attachPartnerTypingListener();
}

function detachListeners(){
  if (!pairCode) return;
  try{
    const nodeRef = ref(db, `peacepage/messages/${pairCode}`);
    off(nodeRef);
    // Detach typing listener
    if (partnerTypingUnsub) {
      partnerTypingUnsub();
      partnerTypingUnsub = null;
    }
  }catch(e){ /* ignore */ }
  attached = false;
}

/* -------------------- Send message (encrypt then push) -------------------- */
async function sendMessage(plain){
  if (!pairCode){ showModal(pairModal); setStatus('no pairing'); return; }
  setStatus('validating pairing...');
  const remoteInfo = await readRemotePairInfo(pairCode);
  if (!remoteInfo) { 
    showError('No pairing created in cloud. Create first.'); 
    setStatus('no remote'); 
    return; 
  }
  // ensure salt matches
  const remoteSalt = base64ToBuf(remoteInfo.salt);
  // if cryptoKeyCache missing or salt changed -> derive again
  if (!cryptoKeyCache || !pairSalt || (remoteSalt.toString() !== pairSalt.toString())) {
    // re-derive
    cryptoKeyCache = await deriveKeyFromCode(pairCode, remoteSalt);
    pairSalt = remoteSalt;
  }
  try {
    setStatus('encrypting...');
    const { c, iv } = await encryptWithKey(cryptoKeyCache, plain);
    setStatus('sending...');
    await push(ref(db, `peacepage/messages/${pairCode}`), { c, iv, t: Date.now(), sender: clientId() });
    setStatus('sent');
    // Clear typing indicator when message is sent
    setLocalTyping(false);
  } catch(e){
    console.error('send error', e);
    setStatus('send failed');
    showError('Failed to send. Please try again.');
  }
}

/* -------------------- Clear chat / forget -------------------- */
async function clearChat(){
  if (!pairCode) {
    showError('No pairing set.');
    return;
  }
  showModal(clearChatModal);
}

async function doClearChat() {
  hideModal(clearChatModal);
  try{
    await remove(ref(db, `peacepage/messages/${pairCode}`));
    messagesEl.innerHTML = '';
    setStatus('cleared');
  }catch(e){ 
    console.error('clear error', e); 
    showError('Failed to clear. Please try again.'); 
  }
}

function forgetLocal(){
  showModal(forgetModal);
}

function doForgetLocal() {
  hideModal(forgetModal);
  detachListeners();
  localStorage.removeItem(LOCAL_PAIR_KEY);
  pairCode = null;
  messagesEl.innerHTML = '';
  attached = false;
  cryptoKeyCache = null;
  pairSalt = null;
  showModal(pairModal);
  setStatus('forgot pairing');
}

/* -------------------- Typing indicator implementation -------------------- */
const TYPING_PATH = (code, client) => `peacepage/typing/${code}/${client}`;

let typingTimeout = null;
let lastTypingState = false;

// call this when user input changes
function setLocalTyping(isTyping) {
  if (!pairCode) return;
  const myId = clientId();
  const path = TYPING_PATH(pairCode, myId);
  try {
    // write a simple presence object
    set(ref(db, path), { t: Date.now(), typing: !!isTyping }).catch(()=>{});
  } catch(e){ /* ignore */ }
  lastTypingState = !!isTyping;
}

// listener to show partner typing
let partnerTypingUnsub = null;
function attachPartnerTypingListener() {
  if (!pairCode) return;

  // unsubscribe existing
  if (partnerTypingUnsub) partnerTypingUnsub();

  const partnerRef = ref(db, `peacepage/typing/${pairCode}`);
  partnerTypingUnsub = onValue(partnerRef, snap => {
    const all = snap.val() || {};
    const my = clientId();

    // find any other client with typing:true and recent timestamp (<6s)
    let someoneTyping = false;
    const now = Date.now();
    for (const k in all) {
      if (k === my) continue;
      const v = all[k];
      if (v && v.typing && (now - (v.t || 0) < 6000)) { someoneTyping = true; break; }
    }

    showTypingUI(someoneTyping);
  }, (err) => { console.warn('typing listener err', err); });
}

// show / hide typing UI (implement DOM update)
function showTypingUI(on) {
  let el = document.querySelector('.typing-indicator');
  if (!el) {
    el = document.createElement('div');
    el.className = 'typing-indicator';
    el.innerHTML = `<div class="dots"><span>.</span><span>.</span><span>.</span></div><div class="text">Partner is typing…</div>`;
    const composer = document.querySelector('.composer');
    composer.appendChild(el);
  }
  el.style.display = on ? 'flex' : 'none';
}

/* -------------------- UI events wiring -------------------- */
sendBtn.addEventListener('click', ()=>{ 
  const t = (textEl.value || '').trim(); 
  if (!t) return; 
  sendMessage(t); 
  textEl.value=''; 
  textEl.style.height = 'auto';
});

textEl.addEventListener('keydown', e=>{ 
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    sendBtn.click();
  }
});

// Auto-resize textarea and handle typing indicator
let typingDebounce = null;
textEl.addEventListener('input', () => {
  textEl.style.height = 'auto';
  textEl.style.height = Math.min(textEl.scrollHeight, 140) + 'px';

  // Typing indicator logic
  const val = (textEl.value || '').trim();
  const isTyping = val.length > 0;
  setLocalTyping(isTyping);

  // debounce clearing (if user stops typing)
  if (typingDebounce) clearTimeout(typingDebounce);
  typingDebounce = setTimeout(() => {
    setLocalTyping(false);
  }, 2000);
});

clearBtnTop?.addEventListener('click', clearChat);
forgetBtn?.addEventListener('click', forgetLocal);

// Modal event handlers
cancelClearBtn.addEventListener('click', () => hideModal(clearChatModal));
confirmClearBtn.addEventListener('click', doClearChat);
cancelForgetBtn.addEventListener('click', () => hideModal(forgetModal));
confirmForgetBtn.addEventListener('click', doForgetLocal);
closeErrorBtn.addEventListener('click', () => hideModal(errorModal));

// Close modals on overlay click
[clearChatModal, forgetModal, overwriteModal, errorModal, shareModal, encryptionModal].forEach(modal => {
  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      hideModal(modal);
    }
  });
});

/* -------------------- Share room link functionality -------------------- */
function showShareModal(code) {
  const shareUrl = `${window.location.origin}${window.location.pathname}?room=${encodeURIComponent(code)}`;
  shareLinkInput.value = shareUrl;
  showModal(shareModal);
}

function copyShareLink() {
  shareLinkInput.select();
  shareLinkInput.setSelectionRange(0, 99999); // For mobile devices
  try {
    navigator.clipboard.writeText(shareLinkInput.value);
    const originalText = copyLinkBtn.textContent;
    copyLinkBtn.textContent = 'Copied!';
    setTimeout(() => {
      copyLinkBtn.textContent = originalText;
    }, 2000);
  } catch(err) {
    // Fallback for older browsers
    document.execCommand('copy');
    const originalText = copyLinkBtn.textContent;
    copyLinkBtn.textContent = 'Copied!';
    setTimeout(() => {
      copyLinkBtn.textContent = originalText;
    }, 2000);
  }
}

function shareViaWhatsApp() {
  const shareUrl = shareLinkInput.value;
  const text = encodeURIComponent(`Join me on Silent chat: ${shareUrl}`);
  window.open(`https://wa.me/?text=${text}`, '_blank');
}

// Share modal event handlers
copyLinkBtn.addEventListener('click', copyShareLink);
shareWhatsAppBtn.addEventListener('click', shareViaWhatsApp);
closeShareBtn.addEventListener('click', () => hideModal(shareModal));

// Allow clicking on share link input to select all
shareLinkInput.addEventListener('click', function() {
  this.select();
});

/* -------------------- Encryption Info modal -------------------- */
async function bufferToHex(buf) {
  const b = new Uint8Array(buf);
  return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
}

async function exportKeyFingerprint() {
  try {
    if (!cryptoKeyCache) return null;
    // export raw AES key bytes
    const raw = await crypto.subtle.exportKey('raw', cryptoKeyCache);
    const digest = await crypto.subtle.digest('SHA-256', raw);
    const hex = await bufferToHex(digest);
    // Short friendly fingerprint for UI, show full for copying
    return { full: hex, short: hex.slice(0,20) + '...' };
  } catch (e) {
    console.warn('exportKeyFingerprint error', e);
    return null;
  }
}

encryptionBtn?.addEventListener('click', async () => {
  // populate fields
  encSaltEl.textContent = 'Not available';
  encFingerprintEl.textContent = 'Not derived';

  if (pairCode) {
    try {
      const pairingSnap = await get(ref(db, `peacepage/pairing/${pairCode}`));
      if (pairingSnap && pairingSnap.exists()) {
        const info = pairingSnap.val();
        if (info && info.salt) encSaltEl.textContent = info.salt;
      }
    } catch (e) {
      console.warn('read pairing for encryption modal', e);
    }
  }

  if (cryptoKeyCache) {
    const fp = await exportKeyFingerprint();
    if (fp) {
      encFingerprintEl.textContent = fp.full.slice(0,48); // show reasonable length
      encFingerprintEl.setAttribute('data-full-fp', fp.full);
    }
  }

  showModal(encryptionModal);
  // focus for accessibility
  closeEncryptionBtn?.focus();
});

// Copy fingerprint
copyFingerprintBtn?.addEventListener('click', async () => {
  const full = encFingerprintEl?.getAttribute('data-full-fp');
  if (!full) {
    copyFingerprintBtn.textContent = 'No fingerprint';
    setTimeout(()=> copyFingerprintBtn.textContent = 'Copy fingerprint', 1400);
    return;
  }
  try {
    await navigator.clipboard.writeText(full);
    const prev = copyFingerprintBtn.textContent;
    copyFingerprintBtn.textContent = 'Copied!';
    setTimeout(()=> copyFingerprintBtn.textContent = prev, 1600);
  } catch (err) {
    console.warn('copy fingerprint failed', err);
    copyFingerprintBtn.textContent = 'Copy failed';
    setTimeout(()=> copyFingerprintBtn.textContent = 'Copy fingerprint', 1600);
  }
});

// close handler
closeEncryptionBtn?.addEventListener('click', () => hideModal(encryptionModal));

// close on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && encryptionModal && encryptionModal.getAttribute('aria-hidden') === 'false') {
    hideModal(encryptionModal);
  }
});

createPairBtn.addEventListener('click', ()=>{ createBox.style.display='block'; joinBox.style.display='none'; createInput.focus(); });
joinPairBtn.addEventListener('click', ()=>{ joinBox.style.display='block'; createBox.style.display='none'; joinInput.focus(); });

doCreate.addEventListener('click', async ()=>{
  const code = (createInput.value || '').trim();
  if (!code || code.length < 2) {
    showError('Enter a code (2–20 chars).');
    return;
  }
  setStatus('creating pairing...');
  // ensure no overwrite if exists
  const existing = await readRemotePairInfo(code);
  if (existing) { 
    pendingOverwrite = { code, action: 'create' };
    showModal(overwriteModal);
    return;
  }
  const saltBytes = await writeRemotePairInfo(code);
  if (!saltBytes) { 
    showError('Create failed'); 
    setStatus('create failed'); 
    return; 
  }
  // derive key
  cryptoKeyCache = await deriveKeyFromCode(code, saltBytes);
  pairSalt = saltBytes;
  localStorage.setItem(LOCAL_PAIR_KEY, code);
  pairCode = code;
  hideModal(pairModal);
  setStatus('paired (creator)');
  attachListeners();
  // Show share modal after successful creation
  setTimeout(() => {
    showShareModal(code);
  }, 300);
});

cancelOverwriteBtn.addEventListener('click', () => {
  hideModal(overwriteModal);
  pendingOverwrite = null;
});

confirmOverwriteBtn.addEventListener('click', async () => {
  if (!pendingOverwrite) {
    hideModal(overwriteModal);
    return;
  }
  const { code, action } = pendingOverwrite;
  hideModal(overwriteModal);
  pendingOverwrite = null;
  
  if (action === 'create') {
    const saltBytes = await writeRemotePairInfo(code);
    if (!saltBytes) { 
      showError('Create failed'); 
      setStatus('create failed'); 
      return; 
    }
    cryptoKeyCache = await deriveKeyFromCode(code, saltBytes);
    pairSalt = saltBytes;
    localStorage.setItem(LOCAL_PAIR_KEY, code);
    pairCode = code;
    hideModal(pairModal);
    setStatus('paired (creator)');
    attachListeners();
    // Show share modal after successful creation
    setTimeout(() => {
      showShareModal(code);
    }, 300);
  }
});

doJoin.addEventListener('click', async ()=>{
  const code = (joinInput.value || '').trim();
  if (!code) {
    showError('Enter code to join.');
    return;
  }
  setStatus('checking pairing...');
  const remoteInfo = await readRemotePairInfo(code);
  if (!remoteInfo){ 
    showError('No pairing created. Ask other to create.'); 
    setStatus('no remote'); 
    return; 
  }
  const saltBytes = base64ToBuf(remoteInfo.salt);
  // derive key now
  cryptoKeyCache = await deriveKeyFromCode(code, saltBytes);
  pairSalt = saltBytes;
  localStorage.setItem(LOCAL_PAIR_KEY, code);
  pairCode = code;
  hideModal(pairModal);
  setStatus('paired (joined)');
  attachListeners();
});

/* -------------------- Mobile keyboard handling -------------------- */
if (window.visualViewport) {
  window.visualViewport.addEventListener('resize', () => {
    const composer = document.querySelector('.composer');
    if (composer) {
      // Keep composer visible when keyboard opens
      setTimeout(() => {
        chatEl.scrollTo({ top: chatEl.scrollHeight, behavior: 'smooth' });
      }, 100);
    }
  });
}

/* -------------------- Init flow -------------------- */
(async function init(){
  try {
    setStatus('initializing...');
    
    // Check for room parameter in URL
    const urlParams = new URLSearchParams(window.location.search);
    const roomParam = urlParams.get('room');
    
    if (roomParam) {
      // Auto-join flow: prefill join input and open join box
      setStatus('room link detected');
      joinInput.value = roomParam;
      showModal(pairModal);
      joinBox.style.display = 'block';
      createBox.style.display = 'none';
      // Auto-trigger join after a brief delay
      setTimeout(async () => {
        const code = roomParam.trim();
        if (!code) {
          showError('Invalid room code.');
          return;
        }
        setStatus('checking pairing...');
        const remoteInfo = await readRemotePairInfo(code);
        if (!remoteInfo){ 
          showError('No pairing created. Ask other to create.'); 
          setStatus('no remote'); 
          return; 
        }
        const saltBytes = base64ToBuf(remoteInfo.salt);
        // derive key now
        cryptoKeyCache = await deriveKeyFromCode(code, saltBytes);
        pairSalt = saltBytes;
        localStorage.setItem(LOCAL_PAIR_KEY, code);
        pairCode = code;
        hideModal(pairModal);
        setStatus('paired (joined)');
        attachListeners();
        // Clean URL
        window.history.replaceState({}, document.title, window.location.pathname);
      }, 500);
      return;
    }
    
    const local = localStorage.getItem(LOCAL_PAIR_KEY);
    if (!local) {
      showModal(pairModal);
      setStatus('waiting for pairing');
      return;
    }
    // if local exists, try to load remote pairing info and derive key
    const info = await readRemotePairInfo(local);
    if (!info) {
      // remote missing: allow user to create or re-create
      showModal(pairModal);
      setStatus('no remote pairing');
      return;
    }
    // derive key
    const saltBytes = base64ToBuf(info.salt);
    cryptoKeyCache = await deriveKeyFromCode(local, saltBytes);
    pairSalt = saltBytes;
    pairCode = local;
    hideModal(pairModal);
    setStatus('paired (restored)');
    attachListeners();
  } catch(e){
    console.error('init error', e);
    setStatus('init error');
    showModal(pairModal);
  }
})();
