// app.js
// Module-based client. Uses Firebase Realtime Database + WebCrypto E2EE (PBKDF2 -> AES-GCM).

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-analytics.js";
import {
  getDatabase, ref, push, set, get, onChildAdded, onChildRemoved, onChildChanged, onValue, remove, off, update
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
const fullscreenBtn = document.getElementById('fullscreenBtn');
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
const deletePopup = document.getElementById('deletePopup');
const cancelDeleteBtn = document.getElementById('cancelDelete');
const confirmDeleteBtn = document.getElementById('confirmDelete');
const clearChatModal = document.getElementById('clearChatModal');
const cancelClearBtn = document.getElementById('cancelClear');
const confirmClearBtn = document.getElementById('confirmClear');
const forgetModal = document.getElementById('forgetModal');
const cancelForgetBtn = document.getElementById('cancelForget');
const confirmForgetBtn = document.getElementById('confirmForget');
const overwriteModal = document.getElementById('overwriteModal');
const cancelOverwriteBtn = document.getElementById('cancelOverwrite');
const confirmOverwriteBtn = document.getElementById('confirmOverwrite');
const reportModal = document.getElementById('reportModal');
const closeReportBtn = document.getElementById('closeReport');
const errorModal = document.getElementById('errorModal');
const errorText = document.getElementById('errorText');
const closeErrorBtn = document.getElementById('closeError');
const shareModal = document.getElementById('shareModal');
const shareLinkInput = document.getElementById('shareLinkInput');
const copyLinkBtn = document.getElementById('copyLinkBtn');
const shareWhatsAppBtn = document.getElementById('shareWhatsAppBtn');
const closeShareBtn = document.getElementById('closeShareBtn');

let pendingDelete = null; // { id, menuElement }
let pendingOverwrite = null; // { code, saltBytes }

/* -------------------- Local keys/state -------------------- */
const LOCAL_PAIR_KEY = 'peacepage_pair_code_chat_v1';
const CLIENT_ID_KEY = 'peacepage_client_id_v1';
let pairCode = null;
let messagesPath = null;
let attached = false;
let cryptoKeyCache = null; // CryptoKey for AES-GCM
let pairSalt = null; // Uint8Array salt used for PBKDF2
let reactionListeners = new Map(); // messageId -> unsubscribe function

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

/* -------------------- UI: delete popup -------------------- */
function showDeletePopup(id, menuElement){
  pendingDelete = { id, menuElement };
  showModal(deletePopup);
  confirmDeleteBtn.focus();
}
function hideDeletePopup(){
  pendingDelete = null;
  hideModal(deletePopup);
}
cancelDeleteBtn.addEventListener('click', hideDeletePopup);
confirmDeleteBtn.addEventListener('click', async ()=>{
  if (!pendingDelete || !pendingDelete.id) { hideDeletePopup(); return; }
  const id = pendingDelete.id;
  hideDeletePopup();
  try {
    await remove(ref(db, `peacepage/messages/${pairCode}/${id}`));
    // Also remove reactions
    try {
      await remove(ref(db, `peacepage/reactions/${pairCode}/${id}`));
    } catch(e) { /* ignore */ }
    setStatus('deleted');
  } catch (err) {
    console.error('delete msg error', err);
    showError('Delete failed. Please try again.');
  }
});

/* -------------------- Message editing -------------------- */
async function saveMessageEdit(messageId, newText) {
  if (!pairCode || !cryptoKeyCache) {
    showError('Cannot edit: pairing not ready.');
    return false;
  }
  try {
    setStatus('encrypting edit...');
    const { c, iv } = await encryptWithKey(cryptoKeyCache, newText);
    await update(ref(db, `peacepage/messages/${pairCode}/${messageId}`), {
      c, iv, edited: true, editedAt: Date.now()
    });
    setStatus('edit saved');
    
    // Immediately update the DOM for instant feedback
    const rowEl = document.getElementById('msg-' + messageId);
    if (rowEl) {
      const preEl = rowEl.querySelector('.msg-pre');
      const metaEl = rowEl.querySelector('.meta');
      if (preEl) {
        preEl.textContent = newText;
      }
      if (metaEl) {
        // Update meta to show edited label - get original timestamp from data attribute or parse
        const metaText = metaEl.textContent || metaEl.innerText || '';
        const parts = metaText.split(' · ');
        const sender = parts[0] || (rowEl.classList.contains('me') ? 'You' : 'Them');
        // Extract time string, removing any existing (edited) label
        let timeStr = parts[1] ? parts[1].replace(/\(edited\)/g, '').trim() : '';
        if (!timeStr && parts.length > 1) {
          timeStr = parts.slice(1).join(' · ').replace(/\(edited\)/g, '').trim();
        }
        // If no time found, try to get from original timestamp
        if (!timeStr) {
          const originalTime = rowEl.getAttribute('data-timestamp');
          if (originalTime) {
            timeStr = new Date(parseInt(originalTime)).toLocaleString();
          }
        }
        metaEl.innerHTML = sender + ' · ' + timeStr + ' <span class="edited-label">(edited)</span>';
      }
    }
    
    return true;
  } catch(e) {
    console.error('edit error', e);
    showError('Failed to save edit. Please try again.');
    return false;
  }
}

function createEditBox(messageId, currentText, bubbleEl) {
  const editBox = document.createElement('div');
  editBox.className = 'msg-edit-box';
  
  const editInput = document.createElement('textarea');
  editInput.className = 'msg-edit-input';
  editInput.value = currentText;
  editInput.rows = 1;
  editInput.style.fontSize = '16px';
  
  // Auto-resize
  editInput.addEventListener('input', () => {
    editInput.style.height = 'auto';
    editInput.style.height = Math.min(editInput.scrollHeight, 120) + 'px';
  });
  editInput.style.height = Math.min(editInput.scrollHeight, 120) + 'px';
  
  const actions = document.createElement('div');
  actions.className = 'msg-edit-actions';
  
  const saveBtn = document.createElement('button');
  saveBtn.className = 'msg-edit-btn msg-edit-save';
  saveBtn.textContent = 'Save';
  saveBtn.addEventListener('click', async () => {
    const newText = editInput.value.trim();
    if (!newText) {
      editBox.remove();
      return;
    }
    if (newText === currentText) {
      editBox.remove();
      return;
    }
    const saved = await saveMessageEdit(messageId, newText);
    if (saved) {
      editBox.remove();
    }
  });
  
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'msg-edit-btn msg-edit-cancel';
  cancelBtn.textContent = 'Cancel';
  cancelBtn.addEventListener('click', () => {
    editBox.remove();
  });
  
  actions.appendChild(saveBtn);
  actions.appendChild(cancelBtn);
  editBox.appendChild(editInput);
  editBox.appendChild(actions);
  
  // Enter to save, Escape to cancel
  editInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      saveBtn.click();
    } else if (e.key === 'Escape') {
      cancelBtn.click();
    }
  });
  
  editInput.focus();
  editInput.setSelectionRange(editInput.value.length, editInput.value.length);
  
  return editBox;
}

/* -------------------- Reactions -------------------- */
const REACTION_EMOJIS = ['❤️', '👍', '😂', '😮'];

async function toggleReaction(messageId, emoji) {
  if (!pairCode) return;
  const myId = clientId();
  const reactionPath = `peacepage/reactions/${pairCode}/${messageId}/${emoji}/${myId}`;
  const reactionRef = ref(db, reactionPath);
  
  try {
    const snap = await get(reactionRef);
    if (snap.exists()) {
      // Remove reaction
      await remove(reactionRef);
    } else {
      // Add reaction
      await set(reactionRef, { t: Date.now() });
    }
  } catch(e) {
    console.error('reaction toggle error', e);
    showError('Failed to update reaction.');
  }
}

function renderReactions(messageId, reactionsData, rowEl, senderIsMe) {
  const existingReactions = rowEl.querySelector('.msg-reactions-container');
  if (existingReactions) {
    existingReactions.remove();
  }
  
  if (!reactionsData || Object.keys(reactionsData).length === 0) {
    return;
  }
  
  const container = document.createElement('div');
  container.className = 'msg-reactions-container';
  
  const reactionsDiv = document.createElement('div');
  reactionsDiv.className = 'msg-reactions';
  
  // Aggregate reactions
  const aggregated = {};
  for (const emoji of REACTION_EMOJIS) {
    if (reactionsData[emoji]) {
      const count = Object.keys(reactionsData[emoji]).length;
      if (count > 0) {
        aggregated[emoji] = count;
      }
    }
  }
  
  // Render reaction buttons
  for (const emoji of REACTION_EMOJIS) {
    const count = aggregated[emoji] || 0;
    if (count === 0 && Object.keys(aggregated).length > 0) continue; // Skip if no reactions and others exist
    
    const btn = document.createElement('button');
    btn.className = 'reaction-btn';
    if (reactionsData[emoji] && reactionsData[emoji][clientId()]) {
      btn.classList.add('active');
    }
    
    const emojiSpan = document.createElement('span');
    emojiSpan.className = 'reaction-emoji';
    emojiSpan.textContent = emoji;
    
    const countSpan = document.createElement('span');
    countSpan.className = 'reaction-count';
    countSpan.textContent = count > 0 ? count : '';
    
    btn.appendChild(emojiSpan);
    btn.appendChild(countSpan);
    
    btn.addEventListener('click', () => {
      toggleReaction(messageId, emoji);
      btn.classList.add('just-added');
      setTimeout(() => btn.classList.remove('just-added'), 300);
    });
    
    reactionsDiv.appendChild(btn);
  }
  
  // Add reaction picker
  const picker = document.createElement('div');
  picker.className = 'reaction-picker';
  for (const emoji of REACTION_EMOJIS) {
    const pickerBtn = document.createElement('button');
    pickerBtn.className = 'reaction-picker-btn';
    pickerBtn.textContent = emoji;
    pickerBtn.setAttribute('aria-label', `React with ${emoji}`);
    pickerBtn.addEventListener('click', () => {
      toggleReaction(messageId, emoji);
    });
    picker.appendChild(pickerBtn);
  }
  
  container.appendChild(reactionsDiv);
  container.appendChild(picker);
  
  const bubble = rowEl.querySelector('.bubble');
  bubble.appendChild(container);
}

function attachReactionListener(messageId) {
  if (!pairCode || reactionListeners.has(messageId)) return;
  
  const reactionRef = ref(db, `peacepage/reactions/${pairCode}/${messageId}`);
  const rowEl = document.getElementById('msg-' + messageId);
  if (!rowEl) return;
  
  const senderIsMe = rowEl.classList.contains('me');
  
  const unsubscribe = onValue(reactionRef, (snap) => {
    const data = snap.val();
    if (rowEl) {
      renderReactions(messageId, data, rowEl, senderIsMe);
    }
  }, (err) => {
    console.error('reaction listener error', err);
  });
  
  reactionListeners.set(messageId, unsubscribe);
}

function detachReactionListener(messageId) {
  const unsubscribe = reactionListeners.get(messageId);
  if (unsubscribe) {
    unsubscribe();
    reactionListeners.delete(messageId);
  }
}

/* -------------------- Message rendering -------------------- */
function closeAllMenus(){ 
  document.querySelectorAll('.msg-options').forEach(m=> {
    m.classList.remove('show');
    // schedule adding hidden after transition end
    setTimeout(()=> {
      if (!m.classList.contains('show')) m.classList.add('hidden');
    }, 140);
  }); 
  document.querySelectorAll('.msg-row').forEach(r=> r.classList.remove('show-menu')); 
}

function toggleMessageMenu(row, menu) {
  const isHidden = menu.classList.contains('hidden') || !menu.classList.contains('show');
  // close other menus first
  closeAllMenus();

  if (isHidden) {
    const bubble = row.querySelector('.bubble');
    if (!bubble) return;
    const bubbleRect = bubble.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const menuWidth = Math.max(140, menu.offsetWidth || 140);
    const menuHeightEstimate = Math.min(menu.scrollHeight || 200, viewportHeight - 40);

    let left, top;

    if (row.classList.contains('them')) {
      left = bubbleRect.left - menuWidth - 8;
      if (left < 8) left = bubbleRect.right + 8;
    } else {
      left = bubbleRect.right + 8;
      if (left + menuWidth > viewportWidth - 8) left = bubbleRect.left - menuWidth - 8;
    }

    top = bubbleRect.top + 8;
    if (top + menuHeightEstimate > viewportHeight - 8) {
      top = Math.max(8, bubbleRect.bottom - menuHeightEstimate - 8);
    }

    // Set inline fixed positioning BEFORE showing
    Object.assign(menu.style, {
      position: 'fixed',
      left: `${Math.round(left)}px`,
      top: `${Math.round(top)}px`,
      right: 'auto',
      bottom: 'auto',
      zIndex: '12000',
      maxHeight: 'calc(100vh - 20px)',
      overflowY: 'auto',
      visibility: 'hidden' // start hidden, we'll animate in
    });

    // Debug: verify menu items exist
    console.log('Opening menu for', row.id, 'menu items:', Array.from(menu.querySelectorAll('.msg-option')).map(b=>b.textContent.trim()));

    // Remove hidden and animate via .show
    menu.classList.remove('hidden');
    // force reflow so transition works
    void menu.offsetWidth;
    row.classList.add('show-menu');

    // slight delay so CSS transition triggers reliably
    setTimeout(() => {
      menu.classList.add('show');
      menu.style.visibility = 'visible';
    }, 8);

  } else {
    // hide gracefully with animation
    menu.classList.remove('show');
    // after transition completes, mark hidden and clean inline styles
    setTimeout(() => {
      if (!menu.classList.contains('show')) {
        menu.classList.add('hidden');
        menu.style.left = '';
        menu.style.top = '';
        menu.style.position = '';
        menu.style.zIndex = '';
      }
    }, 160); // match CSS transition (~120ms + margin)
    row.classList.remove('show-menu');
  }
}

// Use pointerdown for more immediate behavior and to avoid race with menu show
document.addEventListener('pointerdown', (e) => {
  // if pointerdown on menu or menu button or edit box -> do nothing
  if (e.target.closest('.msg-options') || e.target.closest('.msg-menu-button') || e.target.closest('.msg-edit-box')) {
    return;
  }
  // otherwise close menus
  closeAllMenus();
});

function createMessageElement(id, plainText, meta, senderIsMe, isEdited = false){
  const row = document.createElement('div');
  row.className = 'msg-row ' + (senderIsMe ? 'me' : 'them');
  row.id = 'msg-' + id;
  row.style.position = 'relative';

  const bubble = document.createElement('div');
  bubble.className = 'bubble ' + (senderIsMe ? 'me' : 'them');

  const pre = document.createElement('pre');
  pre.className = 'msg-pre';
  pre.textContent = plainText || '';
  bubble.appendChild(pre);

  const metaEl = document.createElement('div');
  metaEl.className = 'meta';
  let metaText = meta;
  if (isEdited) {
    metaText += ' <span class="edited-label">(edited)</span>';
  }
  metaEl.innerHTML = metaText;
  bubble.appendChild(metaEl);

  // menu button + options
  const menuBtn = document.createElement('button');
  menuBtn.className = 'msg-menu-button';
  menuBtn.setAttribute('aria-label', 'Message menu');
  menuBtn.innerHTML = '&#x25B6;';

  const menu = document.createElement('div');
  menu.className = 'msg-options hidden';

  const optCopy = document.createElement('button');
  optCopy.className = 'msg-option';
  optCopy.textContent = 'Copy';
  optCopy.addEventListener('click', async (ev)=>{
    ev.stopPropagation();
    try {
      await navigator.clipboard.writeText(plainText || '');
      optCopy.textContent = 'Copied';
      setTimeout(()=> optCopy.textContent = 'Copy', 1200);
    } catch(err){
      console.warn('copy fail', err);
      // fallback: select
      const range = document.createRange();
      range.selectNodeContents(pre);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
    menu.classList.add('hidden');
    menu.classList.remove('show');
  });
  menu.appendChild(optCopy);

  if (senderIsMe) {
    const optEdit = document.createElement('button');
    optEdit.className = 'msg-option';
    optEdit.textContent = 'Edit';
    optEdit.addEventListener('click', (ev)=>{
      ev.stopPropagation();
      menu.classList.add('hidden');
      menu.classList.remove('show');
      const existingEdit = bubble.querySelector('.msg-edit-box');
      if (existingEdit) {
        existingEdit.remove();
        return;
      }
      const editBox = createEditBox(id, plainText, bubble);
      bubble.appendChild(editBox);
    });
    menu.appendChild(optEdit);
    
    const optDel = document.createElement('button');
    optDel.className = 'msg-option';
    optDel.textContent = 'Delete';
    optDel.style.color = '#ffb4b4';
    optDel.addEventListener('click', (ev)=>{
      ev.stopPropagation();
      menu.classList.add('hidden');
      menu.classList.remove('show');
      showDeletePopup(id, menu);
    });
    menu.appendChild(optDel);
  }

  const optReport = document.createElement('button');
  optReport.className = 'msg-option';
  optReport.textContent = 'Report';
  optReport.addEventListener('click', async (ev)=>{
    ev.stopPropagation();
    menu.classList.add('hidden');
    menu.classList.remove('show');
    try {
      await push(ref(db, `peacepage/reports/${pairCode || 'ungrouped'}`), {
        messageId: id,
        text: plainText || '',
        sender: senderIsMe ? clientId() : 'them',
        reporter: clientId(),
        t: Date.now()
      });
      showModal(reportModal);
    } catch(err){
      console.error('report error', err);
      showError('Report failed. Please try again.');
    }
  });
  menu.appendChild(optReport);

  row.appendChild(bubble);
  row.appendChild(menuBtn);
  row.appendChild(menu);

  // Use pointerdown (works better on mobile/desktop) and ensure events don't bubble
  menuBtn.setAttribute('tabindex','0'); // accessible
  menuBtn.addEventListener('pointerdown', (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    // defensive: ensure the button is on top
    menuBtn.style.zIndex = '11001';
    menu.style.zIndex = '12001';
    // toggle
    toggleMessageMenu(row, menu);
  });

  // Long press support for mobile
  let longPressTimer = null;
  const handleTouchStart = (e) => {
    longPressTimer = setTimeout(() => {
      e.preventDefault();
      toggleMessageMenu(row, menu);
      row.classList.add('show-menu');
    }, 500); // 500ms for long press
  };
  const handleTouchEnd = () => {
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  };
  const handleTouchMove = () => {
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  };

  bubble.addEventListener('touchstart', handleTouchStart, { passive: false });
  bubble.addEventListener('touchend', handleTouchEnd);
  bubble.addEventListener('touchmove', handleTouchMove);
  bubble.addEventListener('touchcancel', handleTouchEnd);

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
    const firstChild = messagesEl.firstChild;
    const firstId = firstChild.id.replace('msg-', '');
    detachReactionListener(firstId);
    messagesEl.removeChild(firstChild);
  }
  
  // Scroll to bottom smoothly
  setTimeout(() => {
    chatEl.scrollTo({ top: chatEl.scrollHeight, behavior: 'smooth' });
  }, 50);
  
  flash110();
  
  // Attach reaction listener
  attachReactionListener(id);
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
    detachReactionListener(id);
  }, err => {
    console.error('onChildRemoved error', err);
  });

  // Listen for message updates (edits) using onChildChanged
  onChildChanged(nodeRef, async snap => {
    const id = snap.key;
    const d = snap.val();
    if (!d) return;
    
    const rowEl = document.getElementById('msg-' + id);
    if (!rowEl) return; // Message doesn't exist in DOM yet
    
    // Decrypt and update the message
    if (d.c && d.iv) {
      try {
        const plain = await decryptWithKey(cryptoKeyCache, d.c, d.iv);
        const preEl = rowEl.querySelector('.msg-pre');
        const metaEl = rowEl.querySelector('.meta');
        
        if (preEl) {
          preEl.textContent = plain;
        }
        
        if (metaEl) {
          const isMine = d.sender === clientId();
          const timeStr = d.t ? new Date(d.t).toLocaleString() : '';
          const isEdited = d.edited === true;
          let metaText = (isMine ? 'You' : 'Them') + ' · ' + timeStr;
          if (isEdited) {
            metaText += ' <span class="edited-label">(edited)</span>';
          }
          metaEl.innerHTML = metaText;
        }
      } catch(e) {
        console.warn('decrypt failed on update', e);
      }
    }
  }, err => {
    console.error('onChildChanged error', err);
  });
}

function detachListeners(){
  if (!pairCode) return;
  try{
    const nodeRef = ref(db, `peacepage/messages/${pairCode}`);
    off(nodeRef);
    // Detach all reaction listeners
    reactionListeners.forEach((unsubscribe) => unsubscribe());
    reactionListeners.clear();
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
    // Clear reactions too
    try {
      await remove(ref(db, `peacepage/reactions/${pairCode}`));
    } catch(e) { /* ignore */ }
    messagesEl.innerHTML = '';
    reactionListeners.forEach((unsubscribe) => unsubscribe());
    reactionListeners.clear();
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
  reactionListeners.forEach((unsubscribe) => unsubscribe());
  reactionListeners.clear();
  attached = false;
  cryptoKeyCache = null;
  pairSalt = null;
  showModal(pairModal);
  setStatus('forgot pairing');
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

// Auto-resize textarea
textEl.addEventListener('input', () => {
  textEl.style.height = 'auto';
  textEl.style.height = Math.min(textEl.scrollHeight, 140) + 'px';
});

clearBtnTop?.addEventListener('click', clearChat);
forgetBtn?.addEventListener('click', forgetLocal);
fullscreenBtn?.addEventListener('click', ()=>{ 
  const el=document.documentElement; 
  if (!document.fullscreenElement) el.requestFullscreen?.(); 
  else document.exitFullscreen?.(); 
});

// Modal event handlers
cancelClearBtn.addEventListener('click', () => hideModal(clearChatModal));
confirmClearBtn.addEventListener('click', doClearChat);
cancelForgetBtn.addEventListener('click', () => hideModal(forgetModal));
confirmForgetBtn.addEventListener('click', doForgetLocal);
closeReportBtn.addEventListener('click', () => hideModal(reportModal));
closeErrorBtn.addEventListener('click', () => hideModal(errorModal));

// Close modals on overlay click
[deletePopup, clearChatModal, forgetModal, overwriteModal, reportModal, errorModal, shareModal].forEach(modal => {
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
