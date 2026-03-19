import { WebSocketServer, WebSocket } from 'ws';
import Database from 'better-sqlite3';

// Initialize SQLite — add tags column if it doesn't exist yet (migration)
const db = new Database('vault_events.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    pubkey      TEXT,
    created_at  INTEGER,
    kind        INTEGER,
    tags        TEXT DEFAULT '[]',
    content     TEXT,
    sig         TEXT
  )
`);
try { db.exec(`ALTER TABLE events ADD COLUMN tags TEXT DEFAULT '[]'`); } catch { /* column already exists */ }

// Only these kinds are accepted:
//   1059  — NIP-59 gift-wrap (PQC encrypted message)
//   11111 — identity announcement (carries the sender's XWing public key)
const ALLOWED_KINDS = new Set([1059, 11111]);

type Filter = {
  kinds?:   number[];
  authors?: string[];
  '#p'?:    string[];
};

function eventMatchesFilter(event: any, filter: Filter): boolean {
  if (filter.kinds   && !filter.kinds.includes(event.kind))     return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter['#p']) {
    const tags: string[][] = typeof event.tags === 'string'
      ? JSON.parse(event.tags)
      : (event.tags ?? []);
    const pValues = tags.filter(t => t[0] === 'p').map(t => t[1]);
    if (!filter['#p'].some(p => pValues.includes(p))) return false;
  }
  return true;
}

// Per-connection subscription map: subId -> filters[]
const subscriptions = new Map<WebSocket, Map<string, Filter[]>>();

const wss = new WebSocketServer({ port: 8080 });
console.log('🛡️  The Vault Relay running on ws://localhost:8080');

wss.on('connection', (ws: WebSocket) => {
  subscriptions.set(ws, new Map());

  ws.on('close', () => subscriptions.delete(ws));

  ws.on('message', (raw: Buffer) => {
    let parsed: any;
    try { parsed = JSON.parse(raw.toString()); } catch { return; }

    const verb = parsed[0];

    // --- REQ: subscribe + replay stored events ---
    if (verb === 'REQ') {
      const [, subId, ...filters] = parsed as [string, string, ...Filter[]];
      subscriptions.get(ws)!.set(subId, filters);

      const rows = db.prepare('SELECT * FROM events ORDER BY created_at ASC').all() as any[];
      for (const row of rows) {
        const ev = { ...row, tags: JSON.parse(row.tags ?? '[]') };
        if (filters.some(f => eventMatchesFilter(ev, f))) {
          ws.send(JSON.stringify(['EVENT', subId, ev]));
        }
      }
      ws.send(JSON.stringify(['EOSE', subId]));
      return;
    }

    // --- CLOSE: cancel a subscription ---
    if (verb === 'CLOSE') {
      subscriptions.get(ws)?.delete(parsed[1]);
      return;
    }

    // --- EVENT: store and broadcast ---
    if (verb === 'EVENT') {
      const event = parsed[1];

      if (!ALLOWED_KINDS.has(event.kind)) {
        ws.send(JSON.stringify(['OK', event.id, false, 'restricted: kind not allowed']));
        return;
      }

      try {
        // NIP-01: Replaceable events (10000-19999) — keep only latest per pubkey+kind
        if (event.kind >= 10000 && event.kind < 20000) {
          db.prepare('DELETE FROM events WHERE pubkey = ? AND kind = ?').run(event.pubkey, event.kind);
        }

        db.prepare(
          'INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(
          event.id, event.pubkey, event.created_at, event.kind,
          JSON.stringify(event.tags ?? []), event.content, event.sig
        );

        ws.send(JSON.stringify(['OK', event.id, true, 'accepted']));
        console.log(`[Relay] kind:${event.kind} from ${event.pubkey.slice(0, 8)}... stored & routing`);

        // Broadcast to all other clients whose subscriptions match this event
        wss.clients.forEach(client => {
          if (client === ws || client.readyState !== WebSocket.OPEN) return;
          subscriptions.get(client)?.forEach((filters, subId) => {
            if (filters.some(f => eventMatchesFilter(event, f))) {
              client.send(JSON.stringify(['EVENT', subId, event]));
            }
          });
        });

      } catch {
        ws.send(JSON.stringify(['OK', event.id, false, 'error: db write failed']));
      }
    }
  });
});
