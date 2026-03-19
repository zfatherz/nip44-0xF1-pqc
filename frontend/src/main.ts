import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools';
import { deriveXWingKeypair, encrypt_v0xF1, decrypt_v0xF1 } from './nip44.ts';
import { sha256 } from '@noble/hashes/sha2.js';

// ═══════════════════════════════════════════════════════════
//  TYPES
// ═══════════════════════════════════════════════════════════

interface ChatMessage {
  id:        string;          // Nostr event id — used for dedup + delivery tracking
  from:      'me' | string;   // 'me' or sender nostrPubkey
  text:      string;
  ts:        number;          // unix seconds
  delivered: boolean;         // true once relay replies OK
}

interface Contact {
  nostrPubkey:    string;
  xwingPubkeyB64: string | null;  // base64 XWing pubkey, null until first kind:11111 seen
  alias:          string;
  lastSeen:       number | null;  // unix ts of their most recent kind:11111
  unread:         number;
  messages:       ChatMessage[];
}

// ═══════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════

let mySecret:      Uint8Array | null = null;
let myNostrPubkey: string     | null = null;
let myXWing:       ReturnType<typeof deriveXWingKeypair> | null = null;

const contacts  = new Map<string, Contact>(); // nostrPubkey → Contact
let   activeConv: string | null = null;       // nostrPubkey of open conversation
const seenIds   = new Set<string>();          // dedup incoming events

let ws:            WebSocket | null = null;
let wsGen          = 0;
let presenceTimer: ReturnType<typeof setInterval> | null = null;

// ═══════════════════════════════════════════════════════════
//  ENCODING
// ═══════════════════════════════════════════════════════════

function b64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
}
function unb64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
function hexToBytes(hex: string): Uint8Array {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) a[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return a;
}

// ═══════════════════════════════════════════════════════════
//  KEY FINGERPRINT
//  First 8 bytes of sha256(xwingPubkey) rendered as colored hex spans.
//  Both peers display EACH OTHER's fingerprint — verbal comparison
//  confirms no man-in-the-middle substitution.
// ═══════════════════════════════════════════════════════════

function fingerprintHTML(keyBytes: Uint8Array): string {
  const h = sha256(keyBytes);
  return Array.from(h.slice(0, 8)).map(b => {
    const hex = b.toString(16).padStart(2, '0').toUpperCase();
    const hue = Math.round((b / 255) * 300);
    return `<span class="fp-byte" style="color:hsl(${hue},100%,60%)">${hex}</span>`;
  }).join('');
}

// ═══════════════════════════════════════════════════════════
//  PERSISTENCE  (localStorage)
// ═══════════════════════════════════════════════════════════

function saveIdentity() {
  if (!mySecret) return;
  const hex = Array.from(mySecret, b => b.toString(16).padStart(2, '0')).join('');
  localStorage.setItem('vault_nsec', hex);
}

function loadIdentity(): boolean {
  const hex = localStorage.getItem('vault_nsec');
  if (!hex || hex.length !== 64) return false;
  mySecret      = hexToBytes(hex);
  myNostrPubkey = getPublicKey(mySecret);
  myXWing       = deriveXWingKeypair(mySecret);
  return true;
}

function saveContacts() {
  const data = Array.from(contacts.values()).map(c => ({
    ...c,
    messages: c.messages.slice(-100), // cap at 100 messages per contact
  }));
  localStorage.setItem('vault_contacts', JSON.stringify(data));
}

function loadContacts() {
  try {
    const raw = localStorage.getItem('vault_contacts');
    if (!raw) return;
    for (const c of JSON.parse(raw) as Contact[]) contacts.set(c.nostrPubkey, c);
  } catch { /* ignore corrupt storage */ }
}

// ═══════════════════════════════════════════════════════════
//  TIME HELPER
// ═══════════════════════════════════════════════════════════

function relTime(ts: number | null): string {
  if (!ts) return 'never';
  const d = Math.floor(Date.now() / 1000) - ts;
  if (d < 60)    return 'now';
  if (d < 3600)  return `${Math.floor(d / 60)}m`;
  if (d < 86400) return `${Math.floor(d / 3600)}h`;
  return `${Math.floor(d / 86400)}d`;
}

// ═══════════════════════════════════════════════════════════
//  UI RENDER
// ═══════════════════════════════════════════════════════════

function log(msg: string) {
  const el = document.getElementById('logs')!;
  el.innerHTML += `<div>&gt; ${msg}</div>`;
  el.scrollTop = el.scrollHeight;
}

function setRelayStatus(ok: boolean) {
  const el = document.getElementById('relay-status')!;
  el.textContent = ok ? '● Connected' : '● Disconnected';
  el.style.color  = ok ? '#0f0' : '#f44';
}

function updateTitle() {
  const total = Array.from(contacts.values()).reduce((n, c) => n + c.unread, 0);
  document.title = total > 0 ? `(${total}) The Vault: v0xF1 PQC Chat` : 'The Vault: v0xF1 — PQC Chat';
}

function renderContacts() {
  const el = document.getElementById('contact-list')!;
  if (!contacts.size) {
    el.innerHTML = '<div class="no-contacts">No contacts yet.<br>Add a peer by their Chat ID.</div>';
    return;
  }
  el.innerHTML = Array.from(contacts.values()).map(c => {
    const online    = c.lastSeen && (Date.now() / 1000 - c.lastSeen < 120);
    const dot       = `<span class="contact-online" style="color:${online ? '#0f0' : '#222'}">●</span>`;
    const badge     = c.unread ? `<span class="badge">${c.unread}</span>` : '';
    const active    = c.nostrPubkey === activeConv ? ' active' : '';
    return `<div class="contact-item${active}" data-pk="${c.nostrPubkey}">
      ${dot}
      <span class="contact-name">${escHtml(c.alias)}</span>
      ${badge}
      <span class="contact-seen">${relTime(c.lastSeen)}</span>
    </div>`;
  }).join('');
  el.querySelectorAll<HTMLElement>('.contact-item').forEach(el => {
    el.addEventListener('click', () => openConversation(el.dataset.pk!));
  });
}

function renderChat() {
  if (!activeConv) {
    document.getElementById('chat-area')!.style.display        = 'none';
    document.getElementById('chat-placeholder')!.style.display = 'flex';
    return;
  }
  const c = contacts.get(activeConv);
  if (!c) return;

  document.getElementById('chat-placeholder')!.style.display = 'none';
  document.getElementById('chat-area')!.style.display        = 'flex';

  // Header
  document.getElementById('chat-peer-name')!.textContent   = c.alias;
  document.getElementById('chat-peer-pubkey')!.textContent = c.nostrPubkey.slice(0, 16) + '…';

  // Peer fingerprint — user compares this with what the peer sees as THEIR own fingerprint
  const fpEl = document.getElementById('chat-peer-fp')!;
  if (c.xwingPubkeyB64) {
    fpEl.innerHTML = fingerprintHTML(unb64(c.xwingPubkeyB64));
    fpEl.title = 'Peer key fingerprint — verify verbally';
    document.getElementById('chat-peer-lock')!.innerHTML = '<span style="color:#0f0">🔐 PQC</span>';
  } else {
    fpEl.innerHTML = '';
    document.getElementById('chat-peer-lock')!.innerHTML = '<span style="color:#fa0">⚠️ Awaiting key</span>';
  }

  // Messages
  const msgsEl = document.getElementById('chat-messages')!;
  msgsEl.innerHTML = c.messages.map(m => {
    const time = new Date(m.ts * 1000).toLocaleTimeString();
    const who  = m.from === 'me'
      ? `<span class="msg-me">YOU</span>`
      : `<span class="msg-them">${escHtml(contacts.get(m.from)?.alias ?? m.from.slice(0, 8) + '…')}</span>`;
    const tick = m.from === 'me'
      ? (m.delivered ? ' <span class="tick done">✓✓</span>' : ' <span class="tick">✓</span>')
      : '';
    return `<div class="msg"><span class="msg-ts">[${time}]</span> ${who}: ${escHtml(m.text)}${tick}</div>`;
  }).join('');
  msgsEl.scrollTop = msgsEl.scrollHeight;

  // Enable input only when we have the peer's key
  const inp = document.getElementById('input-msg') as HTMLInputElement;
  const btn = document.getElementById('btn-send')  as HTMLButtonElement;
  inp.disabled = !c.xwingPubkeyB64;
  btn.disabled = !c.xwingPubkeyB64;
  inp.placeholder = c.xwingPubkeyB64 ? 'Type your PQC-encrypted message…' : 'Waiting for peer key…';
}

function openConversation(pubkey: string) {
  activeConv = pubkey;
  const c = contacts.get(pubkey)!;
  c.unread = 0;
  saveContacts();
  renderContacts();
  renderChat();
  updateTitle();
  document.getElementById('input-msg')?.focus();
}

function escHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ═══════════════════════════════════════════════════════════
//  RELAY
// ═══════════════════════════════════════════════════════════

function connectRelay() {
  const myGen = ++wsGen;
  ws = new WebSocket('ws://localhost:8080');

  ws.onopen = () => {
    if (wsGen !== myGen) return;
    setRelayStatus(true);
    log('[Relay] Connected.');
    if (myNostrPubkey) { subscribeAll(); publishIdentity(); startPresence(); }
  };

  ws.onclose = () => {
    if (wsGen !== myGen) return;
    setRelayStatus(false);
    if (presenceTimer) { clearInterval(presenceTimer); presenceTimer = null; }
    log('[Relay] Disconnected — retrying in 3 s…');
    setTimeout(() => { if (wsGen === myGen) connectRelay(); }, 3000);
  };

  ws.onerror  = () => log('[Relay] WebSocket error.');
  ws.onmessage = (e) => {
    if (wsGen !== myGen) return;
    try { handleRelayMsg(JSON.parse(e.data)); } catch { /* ignore malformed */ }
  };
}

function subscribeAll() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !myNostrPubkey) return;
  ws.send(JSON.stringify(['REQ', 'inbox', { kinds: [1059],  '#p': [myNostrPubkey] }]));
  ws.send(JSON.stringify(['REQ', 'ids',   { kinds: [11111] }]));
  log(`[Relay] Subscribed as ${myNostrPubkey.slice(0, 8)}…`);
}

function publishIdentity() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !mySecret || !myXWing) return;
  const ev = finalizeEvent({
    kind: 11111, created_at: Math.floor(Date.now() / 1000),
    tags: [], content: b64(myXWing.publicKey),
  }, mySecret);
  ws.send(JSON.stringify(['EVENT', ev]));
  document.getElementById('xwing-status')!.textContent = 'Published ✓';
  document.getElementById('xwing-status')!.style.color = '#0f0';
}

// Re-publish identity every 60 s as a presence heartbeat
function startPresence() {
  if (presenceTimer) clearInterval(presenceTimer);
  presenceTimer = setInterval(publishIdentity, 60_000);
}

// ═══════════════════════════════════════════════════════════
//  RELAY MESSAGE HANDLER
// ═══════════════════════════════════════════════════════════

function handleRelayMsg(msg: any[]) {

  // Delivery receipt: mark the matching outgoing message as delivered (✓✓)
  if (msg[0] === 'OK') {
    const [, eventId, ok, reason] = msg;
    if (ok) {
      for (const c of contacts.values()) {
        const m = c.messages.find(m => m.id === eventId);
        if (m) { m.delivered = true; saveContacts(); if (activeConv === c.nostrPubkey) renderChat(); break; }
      }
    } else {
      log(`[Relay] Rejected: ${reason}`);
    }
    return;
  }

  if (msg[0] === 'EOSE') { log(`[Relay] Caught up on "${msg[1]}".`); return; }
  if (msg[0] !== 'EVENT') return;

  const [, , event] = msg;

  // Dedup — relay may replay stored events on subscription
  if (seenIds.has(event.id)) return;
  seenIds.add(event.id);

  // ── kind:11111 — Identity / presence announcement ──
  if (event.kind === 11111) {
    try {
      const sender = event.pubkey as string;
      const xB64   = event.content as string;
      if (!contacts.has(sender)) {
        contacts.set(sender, {
          nostrPubkey: sender, xwingPubkeyB64: xB64, alias: sender.slice(0, 8) + '…',
          lastSeen: event.created_at, unread: 0, messages: [],
        });
        log(`[Identity] New peer: ${sender.slice(0, 8)}…`);
      } else {
        const c = contacts.get(sender)!;
        c.xwingPubkeyB64 = xB64;
        c.lastSeen       = event.created_at;
      }
      saveContacts();
      renderContacts();
      if (activeConv === sender) renderChat(); // refresh lock/fingerprint
    } catch { /* ignore bad base64 */ }
    return;
  }

  // ── kind:1059 — Incoming encrypted message ──
  if (event.kind === 1059) {
    const addressed = (event.tags as string[][]).some(t => t[0] === 'p' && t[1] === myNostrPubkey);
    if (!addressed || !myXWing) return;

    try {
      // ── Telemetry: decryption probe ──
      const startTime = performance.now();

      const plainBytes = decrypt_v0xF1(myXWing.secretKey, unb64(event.content));

      // ── Probe end ──
      const decodeTime = performance.now() - startTime;

      // Payload is JSON {msg, from, ts} — the `from` field lets the recipient display
      // the sender's identity even before we've fetched their kind:11111.
      // Note: `from` is self-reported inside the encryption (confidential but not
      // cryptographically bound without a Schnorr signature — adequate for demo).
      let text = '';
      let from = event.pubkey as string;
      try {
        const p = JSON.parse(new TextDecoder().decode(plainBytes));
        text = typeof p.msg === 'string' ? p.msg : new TextDecoder().decode(plainBytes);
        from = typeof p.from === 'string' ? p.from : from;
      } catch {
        text = new TextDecoder().decode(plainBytes);
      }

      if (!contacts.has(from)) {
        contacts.set(from, {
          nostrPubkey: from, xwingPubkeyB64: null, alias: from.slice(0, 8) + '…',
          lastSeen: null, unread: 0, messages: [],
        });
      }
      const c = contacts.get(from)!;
      c.messages.push({ id: event.id, from, text, ts: event.created_at, delivered: true });

      if (activeConv !== from || document.hidden) c.unread++;

      saveContacts();
      renderContacts();
      updateTitle();
      if (activeConv === from) renderChat();
      log(`[Crypto] Decapsulated & Decrypted in ${decodeTime.toFixed(2)} ms from ${from.slice(0, 8)}…`);
    } catch (e: any) {
      log(`[Error] Decrypt failed: ${e.message}`);
    }
  }
}

// ═══════════════════════════════════════════════════════════
//  SEND
// ═══════════════════════════════════════════════════════════

function sendMessage() {
  const input = document.getElementById('input-msg') as HTMLInputElement;
  const text  = input.value.trim();
  if (!text || !activeConv || !mySecret || !myNostrPubkey) return;
  const c = contacts.get(activeConv);
  if (!c?.xwingPubkeyB64) return;
  if (!ws || ws.readyState !== WebSocket.OPEN) { log('[Error] Relay not connected.'); return; }

  try {
    const payload = JSON.stringify({ msg: text, from: myNostrPubkey, ts: Math.floor(Date.now() / 1000) });

    // ── Telemetry: encryption probe ──
    const startTime = performance.now();

    const cipher  = encrypt_v0xF1(unb64(c.xwingPubkeyB64), new TextEncoder().encode(payload));

    // ── Probe end ──
    const encodeTime = performance.now() - startTime;

    const ev = finalizeEvent({
      kind: 1059, created_at: Math.floor(Date.now() / 1000),
      tags: [['p', activeConv]], content: b64(cipher),
    }, mySecret);

    // Optimistic UI: add message immediately with delivered=false (single ✓)
    c.messages.push({ id: ev.id, from: 'me', text, ts: ev.created_at, delivered: false });
    saveContacts();
    renderChat();

    ws.send(JSON.stringify(['EVENT', ev]));
    input.value = '';
    log(`[Crypto] Encrypted & Encapsulated in ${encodeTime.toFixed(2)} ms. Sent → ${activeConv.slice(0, 8)}…`);
  } catch (e: any) {
    log(`[Error] Send failed: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════
//  BUTTON HANDLERS
// ═══════════════════════════════════════════════════════════

function applyIdentity() {
  document.getElementById('my-chat-id')!.textContent        = myNostrPubkey!;
  document.getElementById('my-fingerprint')!.innerHTML      = myXWing ? fingerprintHTML(myXWing.publicKey) : '';
  (document.getElementById('identity-block') as HTMLElement).style.display = 'flex';
}

// Generate (or regenerate) burner identity
document.getElementById('btn-generate')!.addEventListener('click', () => {
  mySecret      = generateSecretKey();
  myNostrPubkey = getPublicKey(mySecret);
  myXWing       = deriveXWingKeypair(mySecret);
  saveIdentity();
  applyIdentity();
  log(`[Identity] New burner: ${myNostrPubkey.slice(0, 16)}…`);
  if (ws && ws.readyState === WebSocket.OPEN) { subscribeAll(); publishIdentity(); }
  else connectRelay();
});

// Copy Chat ID to clipboard
document.getElementById('btn-copy-id')!.addEventListener('click', () => {
  navigator.clipboard.writeText(myNostrPubkey ?? '').then(() => {
    const b = document.getElementById('btn-copy-id')!;
    b.textContent = 'Copied ✓';
    setTimeout(() => { b.textContent = 'Copy Chat ID'; }, 2000);
  });
});

// Add contact (and optionally set an alias)
document.getElementById('btn-add-contact')!.addEventListener('click', addContact);
document.getElementById('input-new-peer')!.addEventListener('keydown', e => {
  if ((e as KeyboardEvent).key === 'Enter') addContact();
});

function addContact() {
  if (!myNostrPubkey) { log('[Error] Generate your identity first.'); return; }
  const inp   = document.getElementById('input-new-peer') as HTMLInputElement;
  const aliEl = document.getElementById('input-alias')    as HTMLInputElement;
  const pk    = inp.value.trim().toLowerCase();
  if (pk.length !== 64 || !/^[0-9a-f]+$/.test(pk)) {
    log('[Error] Invalid Chat ID — must be 64-char hex.');
    return;
  }
  const alias = aliEl.value.trim() || pk.slice(0, 8) + '…';
  if (!contacts.has(pk)) {
    contacts.set(pk, { nostrPubkey: pk, xwingPubkeyB64: null, alias, lastSeen: null, unread: 0, messages: [] });
  } else {
    contacts.get(pk)!.alias = alias;
  }
  inp.value = ''; aliEl.value = '';
  saveContacts();
  renderContacts();
  // Fetch their XWing key from relay
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(['REQ', `lkp-${pk.slice(0, 8)}`, { kinds: [11111], authors: [pk] }]));
    log(`[Relay] Fetching key for ${alias}…`);
  }
  openConversation(pk);
}

// Send on button click or Enter key
document.getElementById('btn-send')!.addEventListener('click', sendMessage);
document.getElementById('input-msg')!.addEventListener('keydown', e => {
  if ((e as KeyboardEvent).key === 'Enter') sendMessage();
});

// Nuke all history
document.getElementById('btn-nuke')!.addEventListener('click', () => {
  if (confirm('⚠️ WARNING: This will permanently delete all contacts and chat history. Proceed?')) {
    // 1. Clear browser storage
    localStorage.removeItem('vault_contacts');
    localStorage.removeItem('vault_nsec');

    // 2. Reset in-memory state
    contacts.clear();
    activeConv = null;
    mySecret = null;
    myNostrPubkey = null;
    myXWing = null;

    // 3. Re-render UI
    renderContacts();
    renderChat();
    updateTitle();
    applyIdentity();

    log('[System] ☢️ All contacts & history nuked from device.');
  }
});

// Clear unread when the tab comes back into focus
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && activeConv) {
    const c = contacts.get(activeConv);
    if (c && c.unread) { c.unread = 0; saveContacts(); renderContacts(); updateTitle(); }
  }
});

// ═══════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════

loadContacts();
renderContacts();

if (loadIdentity()) {
  applyIdentity();
  log('[Identity] Restored from local storage.');
}

connectRelay();
