// Task accounts and sync. Static files are served by Workers Assets; only /api/* reaches this code.
// All data lives in one SQLite-backed Durable Object, so there is nothing to set up in the Cloudflare dashboard.
import { DurableObject } from "cloudflare:workers";

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    if (req.method !== "GET" && req.method !== "POST") return json({ error: "method" }, 405);
    // Same-origin only: the app is the only client.
    const origin = req.headers.get("origin");
    if (origin && origin !== url.origin) return json({ error: "origin" }, 403);
    const stub = env.STORE.get(env.STORE.idFromName("main"));
    return stub.fetch(req);
  }
};

const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
// The browser already stretches the password (PBKDF2, 300k rounds); the server adds a salted, lighter round to stay inside Workers CPU limits.
async function hashKey(clientKey, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(clientKey), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 5000 }, k, 256));
}
function same(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
const cleanEmail = e => String(e || "").trim().toLowerCase();
const okEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200;
const SESSION_DAYS = 90;

export class Store extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, hash TEXT NOT NULL, salt TEXT NOT NULL, created INTEGER, fails INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0);
      CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created INTEGER, seen INTEGER);
      CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, name TEXT, code TEXT UNIQUE, owner TEXT, created INTEGER);
      CREATE TABLE IF NOT EXISTS members (team_id TEXT, user_id TEXT, role TEXT, joined INTEGER, PRIMARY KEY (team_id, user_id));
      CREATE TABLE IF NOT EXISTS items (id TEXT NOT NULL, space TEXT NOT NULL, data TEXT, updated INTEGER NOT NULL, srv INTEGER NOT NULL, deleted INTEGER DEFAULT 0, by_user TEXT, PRIMARY KEY (id));
      CREATE INDEX IF NOT EXISTS items_space_srv ON items (space, srv);
      CREATE TABLE IF NOT EXISTS gone (id TEXT NOT NULL, space TEXT NOT NULL, srv INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS gone_space_srv ON gone (space, srv);
    `);
  }

  one(q, ...a) { return this.sql.exec(q, ...a).toArray()[0] || null; }
  all(q, ...a) { return this.sql.exec(q, ...a).toArray(); }

  async fetch(req) {
    const url = new URL(req.url), path = url.pathname.slice(5);
    let body = {};
    if (req.method === "POST") { try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); } }
    try {
      if (path === "health") return json({ ok: true });
      if (path === "signup") return this.signup(body);
      if (path === "login") return this.login(body);
      const user = await this.auth(req);
      if (!user) return json({ error: "signed_out" }, 401);
      if (path === "logout") { this.sql.exec("DELETE FROM sessions WHERE token = ?", await sha(this.bearer(req))); return json({ ok: true }); }
      if (path === "me") return json(this.me(user));
      if (path === "team/join") return this.join(user, body);
      if (path === "team/rename") return this.renameTeam(user, body);
      if (path === "sync") return this.sync(user, body);
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server", message: String(e && e.message || e) }, 500);
    }
  }

  bearer(req) { const h = req.headers.get("authorization") || ""; return h.startsWith("Bearer ") ? h.slice(7) : ""; }
  async auth(req) {
    const t = this.bearer(req); if (!t) return null;
    const s = this.one("SELECT * FROM sessions WHERE token = ?", await sha(t)); if (!s) return null;
    if (Date.now() - s.seen > SESSION_DAYS * 864e5) { this.sql.exec("DELETE FROM sessions WHERE token = ?", s.token); return null; }
    if (Date.now() - s.seen > 36e5) this.sql.exec("UPDATE sessions SET seen = ? WHERE token = ?", Date.now(), s.token);
    return this.one("SELECT id, email, name FROM users WHERE id = ?", s.user_id);
  }
  async session(userId) {
    const token = rand(32);
    this.sql.exec("INSERT INTO sessions (token, user_id, created, seen) VALUES (?, ?, ?, ?)", await sha(token), userId, Date.now(), Date.now());
    return token;
  }
  teamOf(userId) { return this.one("SELECT t.id, t.name, t.code, t.owner, m.role FROM members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = ? ORDER BY m.joined LIMIT 1", userId); }
  me(user) {
    const team = this.teamOf(user.id);
    const members = team ? this.all("SELECT u.name, u.email, m.role FROM members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ? ORDER BY m.joined", team.id) : [];
    return { user, team: team && { id: team.id, name: team.name, code: team.code, role: team.role }, members };
  }

  async signup(b) {
    const email = cleanEmail(b.email), key = String(b.key || ""), name = String(b.name || "").trim().slice(0, 80);
    if (!okEmail(email)) return json({ error: "bad_email" }, 400);
    if (key.length < 32) return json({ error: "bad_password" }, 400);
    if (this.one("SELECT id FROM users WHERE email = ?", email)) return json({ error: "email_taken" }, 409);
    const code = String(b.invite || "").trim().toUpperCase();
    const team = code ? this.one("SELECT * FROM teams WHERE code = ?", code) : null;
    if (code && !team) return json({ error: "bad_invite" }, 400);
    const id = rand(10), salt = rand(16);
    this.sql.exec("INSERT INTO users (id, email, name, hash, salt, created) VALUES (?, ?, ?, ?, ?, ?)", id, email, name, await hashKey(key, salt), salt, Date.now());
    if (team) this.sql.exec("INSERT INTO members (team_id, user_id, role, joined) VALUES (?, ?, 'member', ?)", team.id, id, Date.now());
    else this.createTeam(id, String(b.company || "Brandbridge").trim().slice(0, 60) || "Brandbridge");
    return json({ token: await this.session(id), ...this.me({ id, email, name }) });
  }
  createTeam(userId, name) {
    const tid = rand(10); let code;
    do { code = Array.from(crypto.getRandomValues(new Uint8Array(8)), x => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[x % 32]).join(""); } while (this.one("SELECT id FROM teams WHERE code = ?", code));
    this.sql.exec("INSERT INTO teams (id, name, code, owner, created) VALUES (?, ?, ?, ?, ?)", tid, name, code, userId, Date.now());
    this.sql.exec("INSERT INTO members (team_id, user_id, role, joined) VALUES (?, ?, 'owner', ?)", tid, userId, Date.now());
  }
  async login(b) {
    const email = cleanEmail(b.email), key = String(b.key || "");
    const u = this.one("SELECT * FROM users WHERE email = ?", email);
    if (!u) { await hashKey(key, "x"); return json({ error: "bad_login" }, 401); }
    if (u.locked_until > Date.now()) return json({ error: "locked", until: u.locked_until }, 429);
    if (!same(await hashKey(key, u.salt), u.hash)) {
      const fails = u.fails + 1;
      this.sql.exec("UPDATE users SET fails = ?, locked_until = ? WHERE id = ?", fails >= 8 ? 0 : fails, fails >= 8 ? Date.now() + 15 * 6e4 : 0, u.id);
      return json({ error: fails >= 8 ? "locked" : "bad_login" }, fails >= 8 ? 429 : 401);
    }
    this.sql.exec("UPDATE users SET fails = 0, locked_until = 0 WHERE id = ?", u.id);
    return json({ token: await this.session(u.id), ...this.me({ id: u.id, email: u.email, name: u.name }) });
  }
  join(user, b) {
    const team = this.one("SELECT * FROM teams WHERE code = ?", String(b.code || "").trim().toUpperCase());
    if (!team) return json({ error: "bad_invite" }, 400);
    const cur = this.teamOf(user.id);
    if (cur && cur.id === team.id) return json(this.me(user));
    // Leaving a team you own and share with nobody is fine; otherwise switch membership.
    if (cur) this.sql.exec("DELETE FROM members WHERE team_id = ? AND user_id = ?", cur.id, user.id);
    this.sql.exec("INSERT INTO members (team_id, user_id, role, joined) VALUES (?, ?, 'member', ?)", team.id, user.id, Date.now());
    return json(this.me(user));
  }
  renameTeam(user, b) {
    const t = this.teamOf(user.id); if (!t || t.role !== "owner") return json({ error: "not_owner" }, 403);
    this.sql.exec("UPDATE teams SET name = ? WHERE id = ?", String(b.name || "").trim().slice(0, 60) || t.name, t.id);
    return json(this.me(user));
  }

  // Push local changes, then return everything in the user's spaces changed since `since` (server clock).
  sync(user, b) {
    const team = this.teamOf(user.id);
    const mine = "u:" + user.id, teamSpace = team ? "t:" + team.id : null;
    const allowed = new Set([mine, teamSpace].filter(Boolean));
    const changes = Array.isArray(b.changes) ? b.changes.slice(0, 2000) : [];
    let accepted = 0, srv = Math.max(Date.now(), this.one("SELECT MAX(srv) AS m FROM (SELECT srv FROM items UNION ALL SELECT srv FROM gone)")?.m || 0);
    for (const c of changes) {
      if (!c || typeof c.id !== "string" || c.id.length > 64) continue;
      const space = c.space === "team" && teamSpace ? teamSpace : mine;
      const updated = Number(c.updatedAt) || 0;
      const data = c.deleted ? null : JSON.stringify(c.data || {});
      if (data && data.length > 200000) continue;
      const ex = this.one("SELECT space, updated FROM items WHERE id = ?", c.id);
      if (ex && !allowed.has(ex.space)) continue; // someone else's item
      if (ex && ex.updated > updated) continue;   // server copy is newer
      srv++;
      if (ex && ex.space !== space) {
        // Moved between personal and team: note it in the old space so the other person's devices drop it.
        this.sql.exec("INSERT INTO gone (id, space, srv) VALUES (?, ?, ?)", c.id, ex.space, srv);
        srv++;
        this.sql.exec("UPDATE items SET space = ?, data = ?, updated = ?, srv = ?, deleted = ?, by_user = ? WHERE id = ?", space, data, updated, srv, c.deleted ? 1 : 0, user.id, c.id);
      } else {
        this.sql.exec("INSERT INTO items (id, space, data, updated, srv, deleted, by_user) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET space = excluded.space, data = excluded.data, updated = excluded.updated, srv = excluded.srv, deleted = excluded.deleted, by_user = excluded.by_user",
          c.id, space, data, updated, srv, c.deleted ? 1 : 0, user.id);
      }
      accepted++;
    }
    const since = Number(b.since) || 0;
    const rows = this.all(`SELECT id, space, data, updated, srv, deleted, by_user FROM items WHERE srv > ? AND space IN (${[...allowed].map(() => "?").join(",")}) ORDER BY srv LIMIT 5000`, since, ...allowed);
    const names = Object.fromEntries(this.all("SELECT id, name FROM users WHERE id IN (SELECT DISTINCT by_user FROM items WHERE space IN (" + [...allowed].map(() => "?").join(",") + "))", ...allowed).map(r => [r.id, r.name]));
    const gone = this.all(`SELECT id, srv FROM gone WHERE srv > ? AND space IN (${[...allowed].map(() => "?").join(",")}) ORDER BY srv LIMIT 5000`, since, ...allowed);
    const more = rows.length === 5000;
    const cursor = Math.max(since, more ? rows[rows.length - 1].srv : Math.max(rows.length ? rows[rows.length - 1].srv : 0, gone.length ? gone[gone.length - 1].srv : 0));
    return json({
      accepted, cursor, more, gone: more ? [] : gone.map(g => g.id),
      items: rows.map(r => ({ id: r.id, space: r.space === mine ? "me" : "team", deleted: !!r.deleted, updatedAt: r.updated, by: r.by_user === user.id ? null : names[r.by_user] || null, data: r.deleted ? null : JSON.parse(r.data) }))
    });
  }
}
