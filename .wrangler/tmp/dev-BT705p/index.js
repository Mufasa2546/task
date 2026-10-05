var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker/index.js
import { DurableObject } from "cloudflare:workers";
var CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type" };
var json = /* @__PURE__ */ __name((data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } }), "json");
var worker_default = {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    const stub = env.STORE.get(env.STORE.idFromName("main"));
    if (url.pathname === "/api/hit") {
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
      if (req.method !== "POST") return new Response(null, { status: 405, headers: CORS });
      const h = new Headers(req.headers);
      h.set("x-country", req.cf && req.cf.country || "");
      await stub.fetch(new Request(req.url, { method: "POST", headers: h, body: (await req.text()).slice(0, 2e3) })).catch(() => {
      });
      return new Response(null, { status: 204, headers: CORS });
    }
    if (req.method !== "GET" && req.method !== "POST") return json({ error: "method" }, 405);
    const origin = req.headers.get("origin");
    if (origin && origin !== url.origin) return json({ error: "origin" }, 403);
    return stub.fetch(req);
  }
};
var enc = new TextEncoder();
var hex = /* @__PURE__ */ __name((buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join(""), "hex");
var rand = /* @__PURE__ */ __name((n) => hex(crypto.getRandomValues(new Uint8Array(n))), "rand");
var sha = /* @__PURE__ */ __name(async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s))), "sha");
async function hashKey(clientKey, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(clientKey), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 5e3 }, k, 256));
}
__name(hashKey, "hashKey");
function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
__name(same, "same");
var cleanEmail = /* @__PURE__ */ __name((e) => String(e || "").trim().toLowerCase(), "cleanEmail");
var okEmail = /* @__PURE__ */ __name((e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200, "okEmail");
var SESSION_DAYS = 90;
var TZ_MS = 3 * 36e5;
var dayKey = /* @__PURE__ */ __name((t) => new Date(t + TZ_MS).toISOString().slice(0, 10), "dayKey");
var cleanHost = /* @__PURE__ */ __name((h) => String(h || "").trim().toLowerCase().replace(/^[a-z]+:\/\//, "").split(/[/?#:]/)[0].replace(/^www\./, ""), "cleanHost");
var okHost = /* @__PURE__ */ __name((h) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h) && h.length <= 120, "okHost");
var BOT = /bot|crawl|spider|slurp|headless|lighthouse|facebookexternalhit|embedly|preview|curl|wget|python|axios|node-fetch|go-http|okhttp|java\/|uptime|monitor|pingdom|vercel/i;
var DIMS = ["path", "ref", "country", "device"];
var Store = class extends DurableObject {
  static {
    __name(this, "Store");
  }
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
      CREATE TABLE IF NOT EXISTS sites (domain TEXT PRIMARY KEY, team_id TEXT NOT NULL, added INTEGER, last_hit INTEGER DEFAULT 0);
      CREATE TABLE IF NOT EXISTS stats (site TEXT, day TEXT, dim TEXT, key TEXT, n INTEGER, PRIMARY KEY (site, day, dim, key));
      CREATE TABLE IF NOT EXISTS uv (site TEXT, day TEXT, h TEXT, last INTEGER, PRIMARY KEY (site, day, h));
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    `);
  }
  one(q, ...a) {
    return this.sql.exec(q, ...a).toArray()[0] || null;
  }
  all(q, ...a) {
    return this.sql.exec(q, ...a).toArray();
  }
  async fetch(req) {
    const url = new URL(req.url), path = url.pathname.slice(5);
    let body = {};
    if (req.method === "POST") {
      try {
        body = await req.json();
      } catch {
        return json({ error: "bad_json" }, 400);
      }
    }
    try {
      if (path === "health") return json({ ok: true });
      if (path === "hit") {
        await this.hit(req, body);
        return new Response(null, { status: 204 });
      }
      if (path === "signup") return this.signup(body);
      if (path === "login") return this.login(body);
      const user = await this.auth(req);
      if (!user) return json({ error: "signed_out" }, 401);
      if (path === "logout") {
        this.sql.exec("DELETE FROM sessions WHERE token = ?", await sha(this.bearer(req)));
        return json({ ok: true });
      }
      if (path === "me") return json(this.me(user));
      if (path === "team/join") return this.join(user, body);
      if (path === "team/rename") return this.renameTeam(user, body);
      if (path === "sync") return this.sync(user, body);
      if (path === "sites") return req.method === "POST" ? this.addSite(user, body) : json({ sites: this.sitesOf(user) });
      if (path === "sites/remove") return this.removeSite(user, body);
      if (path === "sites/check") return this.checkSite(user, body);
      if (path === "stats") return this.stats(user, url);
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server", message: String(e && e.message || e) }, 500);
    }
  }
  bearer(req) {
    const h = req.headers.get("authorization") || "";
    return h.startsWith("Bearer ") ? h.slice(7) : "";
  }
  async auth(req) {
    const t = this.bearer(req);
    if (!t) return null;
    const s = this.one("SELECT * FROM sessions WHERE token = ?", await sha(t));
    if (!s) return null;
    if (Date.now() - s.seen > SESSION_DAYS * 864e5) {
      this.sql.exec("DELETE FROM sessions WHERE token = ?", s.token);
      return null;
    }
    if (Date.now() - s.seen > 36e5) this.sql.exec("UPDATE sessions SET seen = ? WHERE token = ?", Date.now(), s.token);
    return this.one("SELECT id, email, name FROM users WHERE id = ?", s.user_id);
  }
  async session(userId) {
    const token = rand(32);
    this.sql.exec("INSERT INTO sessions (token, user_id, created, seen) VALUES (?, ?, ?, ?)", await sha(token), userId, Date.now(), Date.now());
    return token;
  }
  teamOf(userId) {
    return this.one("SELECT t.id, t.name, t.code, t.owner, m.role FROM members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = ? ORDER BY m.joined LIMIT 1", userId);
  }
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
    const tid = rand(10);
    let code;
    do {
      code = Array.from(crypto.getRandomValues(new Uint8Array(8)), (x) => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[x % 32]).join("");
    } while (this.one("SELECT id FROM teams WHERE code = ?", code));
    this.sql.exec("INSERT INTO teams (id, name, code, owner, created) VALUES (?, ?, ?, ?, ?)", tid, name, code, userId, Date.now());
    this.sql.exec("INSERT INTO members (team_id, user_id, role, joined) VALUES (?, ?, 'owner', ?)", tid, userId, Date.now());
  }
  async login(b) {
    const email = cleanEmail(b.email), key = String(b.key || "");
    const u = this.one("SELECT * FROM users WHERE email = ?", email);
    if (!u) {
      await hashKey(key, "x");
      return json({ error: "bad_login" }, 401);
    }
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
    if (cur) this.sql.exec("DELETE FROM members WHERE team_id = ? AND user_id = ?", cur.id, user.id);
    this.sql.exec("INSERT INTO members (team_id, user_id, role, joined) VALUES (?, ?, 'member', ?)", team.id, user.id, Date.now());
    return json(this.me(user));
  }
  renameTeam(user, b) {
    const t = this.teamOf(user.id);
    if (!t || t.role !== "owner") return json({ error: "not_owner" }, 403);
    this.sql.exec("UPDATE teams SET name = ? WHERE id = ?", String(b.name || "").trim().slice(0, 60) || t.name, t.id);
    return json(this.me(user));
  }
  // Push local changes, then return everything in the user's spaces changed since `since` (server clock).
  sync(user, b) {
    const team = this.teamOf(user.id);
    const mine = "u:" + user.id, teamSpace = team ? "t:" + team.id : null;
    const allowed = new Set([mine, teamSpace].filter(Boolean));
    const changes = Array.isArray(b.changes) ? b.changes.slice(0, 2e3) : [];
    let accepted = 0, srv = Math.max(Date.now(), this.one("SELECT MAX(srv) AS m FROM (SELECT srv FROM items UNION ALL SELECT srv FROM gone)")?.m || 0);
    for (const c of changes) {
      if (!c || typeof c.id !== "string" || c.id.length > 64) continue;
      const space = c.space === "team" && teamSpace ? teamSpace : mine;
      const updated = Number(c.updatedAt) || 0;
      const data = c.deleted ? null : JSON.stringify(c.data || {});
      if (data && data.length > 2e5) continue;
      const ex = this.one("SELECT space, updated FROM items WHERE id = ?", c.id);
      if (ex && !allowed.has(ex.space)) continue;
      if (ex && ex.updated > updated) continue;
      srv++;
      if (ex && ex.space !== space) {
        this.sql.exec("INSERT INTO gone (id, space, srv) VALUES (?, ?, ?)", c.id, ex.space, srv);
        srv++;
        this.sql.exec("UPDATE items SET space = ?, data = ?, updated = ?, srv = ?, deleted = ?, by_user = ? WHERE id = ?", space, data, updated, srv, c.deleted ? 1 : 0, user.id, c.id);
      } else {
        this.sql.exec(
          "INSERT INTO items (id, space, data, updated, srv, deleted, by_user) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET space = excluded.space, data = excluded.data, updated = excluded.updated, srv = excluded.srv, deleted = excluded.deleted, by_user = excluded.by_user",
          c.id,
          space,
          data,
          updated,
          srv,
          c.deleted ? 1 : 0,
          user.id
        );
      }
      accepted++;
    }
    const since = Number(b.since) || 0;
    const rows = this.all(`SELECT id, space, data, updated, srv, deleted, by_user FROM items WHERE srv > ? AND space IN (${[...allowed].map(() => "?").join(",")}) ORDER BY srv LIMIT 5000`, since, ...allowed);
    const names = Object.fromEntries(this.all("SELECT id, name FROM users WHERE id IN (SELECT DISTINCT by_user FROM items WHERE space IN (" + [...allowed].map(() => "?").join(",") + "))", ...allowed).map((r) => [r.id, r.name]));
    const gone = this.all(`SELECT id, srv FROM gone WHERE srv > ? AND space IN (${[...allowed].map(() => "?").join(",")}) ORDER BY srv LIMIT 5000`, since, ...allowed);
    const more = rows.length === 5e3;
    const cursor = Math.max(since, more ? rows[rows.length - 1].srv : Math.max(rows.length ? rows[rows.length - 1].srv : 0, gone.length ? gone[gone.length - 1].srv : 0));
    return json({
      accepted,
      cursor,
      more,
      gone: more ? [] : gone.map((g) => g.id),
      items: rows.map((r) => ({ id: r.id, space: r.space === mine ? "me" : "team", deleted: !!r.deleted, updatedAt: r.updated, by: r.by_user === user.id ? null : names[r.by_user] || null, data: r.deleted ? null : JSON.parse(r.data) }))
    });
  }
  // ---------- Website visits ----------
  // No cookies and no stored IP addresses: a visitor is a hash of IP + browser + site with a salt that is
  // thrown away after two days, so the same person counts once per day and can't be followed across days.
  daySalt(day) {
    let row = this.one("SELECT v FROM meta WHERE k = ?", "salt:" + day);
    if (row) return row.v;
    const v = rand(16);
    this.sql.exec("INSERT OR IGNORE INTO meta (k, v) VALUES (?, ?)", "salt:" + day, v);
    const keep = dayKey(Date.now() - 864e5);
    this.sql.exec("DELETE FROM meta WHERE k LIKE 'salt:%' AND k < ?", "salt:" + keep);
    this.sql.exec("DELETE FROM uv WHERE day < ?", keep);
    return this.one("SELECT v FROM meta WHERE k = ?", "salt:" + day).v;
  }
  bump(site, day, dim, key) {
    key = String(key || "").slice(0, 160);
    if (DIMS.includes(dim) && !this.one("SELECT 1 AS x FROM stats WHERE site = ? AND day = ? AND dim = ? AND key = ?", site, day, dim, key) && (this.one("SELECT COUNT(*) AS c FROM stats WHERE site = ? AND day = ? AND dim = ?", site, day, dim)?.c || 0) >= 300) key = "(other)";
    this.sql.exec("INSERT INTO stats (site, day, dim, key, n) VALUES (?, ?, ?, ?, 1) ON CONFLICT(site, day, dim, key) DO UPDATE SET n = n + 1", site, day, dim, key);
  }
  async hit(req, b) {
    const ua = req.headers.get("user-agent") || "";
    if (!ua || BOT.test(ua)) return;
    const site = cleanHost(b.h || b.s);
    if (!site || !this.one("SELECT 1 AS x FROM sites WHERE domain = ?", site)) return;
    const t = Date.now(), day = dayKey(t);
    let path = String(b.p || "/").split(/[?#]/)[0] || "/";
    if (path.length > 1) path = path.replace(/\/+$/, "");
    const h = (await sha(this.daySalt(day) + "|" + (req.headers.get("cf-connecting-ip") || "") + "|" + ua + "|" + site)).slice(0, 20);
    const fresh = !this.one("SELECT 1 AS x FROM uv WHERE site = ? AND day = ? AND h = ?", site, day, h);
    if (fresh) this.sql.exec("INSERT INTO uv (site, day, h, last) VALUES (?, ?, ?, ?)", site, day, h, t);
    else this.sql.exec("UPDATE uv SET last = ? WHERE site = ? AND day = ? AND h = ?", t, site, day, h);
    this.bump(site, day, "pv", "");
    this.bump(site, day, "path", path);
    if (fresh) {
      let ref = "";
      try {
        ref = cleanHost(new URL(String(b.r || "")).hostname);
      } catch {
      }
      if (ref === site) ref = "";
      const w = Number(b.w) || 0;
      this.bump(site, day, "uv", "");
      this.bump(site, day, "ref", ref ? REF_NAMES[ref] || ref : "Direct");
      this.bump(site, day, "country", (req.headers.get("x-country") || "").toUpperCase().slice(0, 2) || "??");
      this.bump(site, day, "device", /iPad|Tablet/i.test(ua) || w >= 600 && w < 1024 && /Mobi|Android/i.test(ua) ? "Tablet" : /Mobi|Android|iPhone/i.test(ua) ? "Phone" : "Computer");
    }
    this.sql.exec("UPDATE sites SET last_hit = ? WHERE domain = ?", t, site);
  }
  sitesOf(user) {
    const team = this.teamOf(user.id);
    if (!team) return [];
    return this.all("SELECT domain, added, last_hit FROM sites WHERE team_id = ? ORDER BY added", team.id);
  }
  addSite(user, b) {
    const team = this.teamOf(user.id);
    if (!team) return json({ error: "no_team" }, 400);
    const domain = cleanHost(b.domain);
    if (!okHost(domain)) return json({ error: "bad_domain" }, 400);
    const ex = this.one("SELECT team_id FROM sites WHERE domain = ?", domain);
    if (ex && ex.team_id !== team.id) return json({ error: "domain_taken" }, 409);
    if (!ex) {
      if (this.one("SELECT COUNT(*) AS c FROM sites WHERE team_id = ?", team.id).c >= 10) return json({ error: "too_many_sites" }, 400);
      this.sql.exec("INSERT INTO sites (domain, team_id, added) VALUES (?, ?, ?)", domain, team.id, Date.now());
    }
    return json({ sites: this.sitesOf(user) });
  }
  removeSite(user, b) {
    const team = this.teamOf(user.id);
    const domain = cleanHost(b.domain);
    if (team && this.one("SELECT 1 AS x FROM sites WHERE domain = ? AND team_id = ?", domain, team.id)) {
      this.sql.exec("DELETE FROM sites WHERE domain = ?", domain);
      this.sql.exec("DELETE FROM stats WHERE site = ?", domain);
      this.sql.exec("DELETE FROM uv WHERE site = ?", domain);
    }
    return json({ sites: this.sitesOf(user) });
  }
  ownSite(user, domain) {
    const team = this.teamOf(user.id);
    domain = cleanHost(domain);
    return team && this.one("SELECT domain, last_hit FROM sites WHERE domain = ? AND team_id = ?", domain, team.id);
  }
  // Loads the site's home page from Cloudflare to say whether it is up and whether the counter is installed.
  async checkSite(user, b) {
    const s = this.ownSite(user, b.domain);
    if (!s) return json({ error: "not_found" }, 404);
    const t0 = Date.now();
    try {
      const r = await fetch("https://" + s.domain + "/", { redirect: "follow", headers: { "user-agent": "TaskSiteCheck/1.0 (+uptime)" }, signal: AbortSignal.timeout(1e4) });
      const html = r.headers.get("content-type")?.includes("html") ? (await r.text()).slice(0, 4e5) : "";
      return json({ up: r.ok, status: r.status, ms: Date.now() - t0, installed: /\/t\.js["'?]/.test(html) && html.includes("task.brandbridgeacademy.workers.dev"), finalUrl: r.url });
    } catch (e) {
      return json({ up: false, status: 0, ms: Date.now() - t0, installed: false, error: String(e && e.message || e).slice(0, 120) });
    }
  }
  stats(user, url) {
    const s = this.ownSite(user, url.searchParams.get("site"));
    if (!s) return json({ error: "not_found" }, 404);
    const n = Math.min(90, Math.max(7, Number(url.searchParams.get("days")) || 30));
    const now = Date.now(), today = dayKey(now), days = [];
    for (let i = n - 1; i >= 0; i--) days.push(dayKey(now - i * 864e5));
    const from = days[0];
    const daily = Object.fromEntries(days.map((d) => [d, { day: d, pv: 0, uv: 0 }]));
    for (const r of this.all("SELECT day, dim, n FROM stats WHERE site = ? AND day >= ? AND dim IN ('pv', 'uv')", s.domain, from)) if (daily[r.day]) daily[r.day][r.dim] = r.n;
    const top = {};
    for (const dim of DIMS) top[dim] = this.all("SELECT key, SUM(n) AS n FROM stats WHERE site = ? AND day >= ? AND dim = ? GROUP BY key ORDER BY n DESC LIMIT 8", s.domain, from, dim).map((r) => [r.key, r.n]);
    const todayTop = this.all("SELECT key, n FROM stats WHERE site = ? AND day = ? AND dim = 'path' ORDER BY n DESC LIMIT 5", s.domain, today).map((r) => [r.key, r.n]);
    const live = this.one("SELECT COUNT(*) AS c FROM uv WHERE site = ? AND day >= ? AND last > ?", s.domain, dayKey(now - 864e5), now - 5 * 6e4)?.c || 0;
    return json({ site: s.domain, lastHit: s.last_hit || 0, today, days: days.map((d) => daily[d]), top, todayTop, live });
  }
};
var REF_NAMES = {
  "google.com": "Google",
  "google.co.ke": "Google",
  "bing.com": "Bing",
  "duckduckgo.com": "DuckDuckGo",
  "facebook.com": "Facebook",
  "m.facebook.com": "Facebook",
  "l.facebook.com": "Facebook",
  "lm.facebook.com": "Facebook",
  "instagram.com": "Instagram",
  "l.instagram.com": "Instagram",
  "t.co": "X (Twitter)",
  "x.com": "X (Twitter)",
  "twitter.com": "X (Twitter)",
  "linkedin.com": "LinkedIn",
  "lnkd.in": "LinkedIn",
  "youtube.com": "YouTube",
  "tiktok.com": "TikTok",
  "wa.me": "WhatsApp",
  "web.whatsapp.com": "WhatsApp",
  "chatgpt.com": "ChatGPT",
  "brandbridgeacademy.site": "Brandbridge Academy",
  "task.brandbridgeacademy.workers.dev": "Task app"
};

// ../../../tmp/claude-0/wr/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../../tmp/claude-0/wr/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    const body = JSON.stringify(error);
    const headers = {
      "Content-Type": "application/json",
      "MF-Experimental-Error-Stack": "true"
    };
    const encoded = encodeURIComponent(body);
    if (encoded.length <= 8192) {
      headers["MF-Experimental-Error-Stack-Payload"] = encoded;
    }
    return new Response(body, { status: 500, headers });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-XhHrCn/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// ../../../tmp/claude-0/wr/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-XhHrCn/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  scheduledTime;
  cron;
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  Store,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
