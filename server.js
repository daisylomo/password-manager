"use strict";
// Backend: a small HTTP API (no dependencies) around the Keychain library.
// The encrypted vault is persisted to vault.json; the SHA-256 checksum goes in a
// separate file (vault.hash) standing in for the "trusted storage" from the handout.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Keychain } = require("./password-manager");
const store = require("./db");

const PORT = process.env.PORT || 3000;
const HASH_FILE = path.join(__dirname, "vault.hash");
const INDEX_FILE = path.join(__dirname, "public", "index.html");

if (!fs.existsSync(INDEX_FILE)) {
  console.error("Missing " + INDEX_FILE + "\nCreate a folder named \"public\" next to server.js and put index.html inside it.");
  process.exit(1);
}

let keychain = null;      // unlocked keychain (in memory only)
let sessionToken = null;  // random token handed to the frontend on unlock

async function persist() {
  const [repr, hash] = await keychain.dump();
  store.save(repr);
  fs.writeFileSync(HASH_FILE, hash);
}


// ---- Item index -------------------------------------------------------------
// The Keychain cannot list its entries (domains are stored only as HMACs), but a
// UI needs a list. So we keep an index INSIDE the keychain: each piece is an
// ordinary encrypted record, so it gets the same padding, swap and rollback
// protection as passwords. Each value is at most 64 characters, as the library requires.
//   "__count"        -> number of items
//   "__idx:<i>"      -> domain of item i
//   "__meta:<domain>"-> "<1|0>|<username>"   (favorite flag + username)
const RESERVED = "__";
const COUNT_KEY = "__count";
const IDX = i => "__idx:" + i;
const META = d => "__meta:" + d;
const MAX_FIELD = 64;
const MAX_USERNAME = 62;   // 64 minus the "1|" prefix

const metaStr = (fav, user) => (fav ? "1" : "0") + "|" + user;
function parseMeta(m) {
  if (m === null || m.length < 2) return { favorite: false, username: "" };
  return { favorite: m[0] === "1", username: m.slice(2) };
}
async function itemCount() {
  const c = await keychain.get(COUNT_KEY);
  return c === null ? 0 : parseInt(c, 10);
}
async function listItems() {
  const n = await itemCount(), items = [];
  for (let i = 0; i < n; i++) {
    const name = await keychain.get(IDX(i));
    items.push({ name, ...parseMeta(await keychain.get(META(name))) });
  }
  return items;
}

function send(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
  });
}

function authorized(req) {
  const t = req.headers["x-session-token"];
  return keychain && sessionToken && typeof t === "string" &&
    t.length === sessionToken.length &&
    crypto.timingSafeEqual(Buffer.from(t), Buffer.from(sessionToken));
}

async function handleApi(req, res) {
  const url = req.url.split("?")[0];
  const body = req.method === "POST" ? await readBody(req) : {};

  if (url === "/api/status") {
    return send(res, 200, { vaultExists: store.exists(), unlocked: authorized(req) });
  }
  if (url === "/api/create") {
    if (store.exists()) return send(res, 409, { error: "Vault already exists" });
    if (!body.password) return send(res, 400, { error: "Password required" });
    keychain = await Keychain.init(body.password);
    await persist();
    sessionToken = crypto.randomBytes(32).toString("hex");
    return send(res, 200, { token: sessionToken });
  }
  if (url === "/api/unlock") {
    if (!store.exists()) return send(res, 404, { error: "No vault" });
    try {
      const repr = store.loadRepr();
      const hash = fs.existsSync(HASH_FILE) ? fs.readFileSync(HASH_FILE, "utf8").trim() : undefined;
      keychain = await Keychain.load(body.password || "", repr, hash);
      sessionToken = crypto.randomBytes(32).toString("hex");
      return send(res, 200, { token: sessionToken });
    } catch (e) {
      keychain = null; sessionToken = null;
      return send(res, 401, { error: "Could not unlock: wrong password or vault tampered with" });
    }
  }

  // Everything below requires an unlocked session
  if (!authorized(req)) return send(res, 401, { error: "Locked" });

  if (url === "/api/lock") { keychain = null; sessionToken = null; return send(res, 200, {}); }
  try {
    if (url === "/api/items") return send(res, 200, { items: await listItems() });

    if (url === "/api/reveal") {
      const value = await keychain.get(String(body.name));
      return send(res, 200, { value });
    }

    if (url === "/api/save") {
      const name = String(body.name || "").trim();
      const username = String(body.username || "");
      const password = body.password === undefined || body.password === "" ? null : String(body.password);
      if (!name) return send(res, 400, { error: "Enter a domain" });
      if (name.length > MAX_FIELD) return send(res, 400, { error: "Domain must be at most " + MAX_FIELD + " characters" });
      if (name.startsWith(RESERVED)) return send(res, 400, { error: "Domains can't start with " + RESERVED });
      if (username.length > MAX_USERNAME) return send(res, 400, { error: "Username must be at most " + MAX_USERNAME + " characters" });
      const existing = await keychain.get(name);
      if (existing === null && password === null) return send(res, 400, { error: "Enter a password" });
      const prev = parseMeta(await keychain.get(META(name)));
      const favorite = body.favorite === undefined ? prev.favorite : !!body.favorite;
      if (password !== null) await keychain.set(name, password);   // validates length first
      await keychain.set(META(name), metaStr(favorite, username));
      if (existing === null) {                                      // new item: add to the encrypted index
        const n = await itemCount();
        await keychain.set(IDX(n), name);
        await keychain.set(COUNT_KEY, String(n + 1));
      }
      await persist();
      return send(res, 200, {});
    }

    if (url === "/api/favorite") {
      const name = String(body.name || "");
      if (await keychain.get(name) === null) return send(res, 404, { error: "No such entry" });
      const prev = parseMeta(await keychain.get(META(name)));
      await keychain.set(META(name), metaStr(!!body.favorite, prev.username));
      await persist();
      return send(res, 200, {});
    }

    if (url === "/api/remove") {
      const name = String(body.name || "");
      const n = await itemCount();
      let pos = -1;
      for (let i = 0; i < n && pos < 0; i++) if (await keychain.get(IDX(i)) === name) pos = i;
      const removed = await keychain.remove(name);
      await keychain.remove(META(name));
      if (pos >= 0) {                                               // keep the index dense: move last into the gap
        const last = await keychain.get(IDX(n - 1));
        if (pos !== n - 1) await keychain.set(IDX(pos), last);
        await keychain.remove(IDX(n - 1));
        await keychain.set(COUNT_KEY, String(n - 1));
      }
      if (removed) await persist();
      return send(res, 200, { removed });
    }
  } catch (e) {
    const tamper = /tamper|authentication|malformed/i.test(e.message);
    return send(res, tamper ? 422 : 400, { error: tamper ? "Tampering detected: " + e.message : e.message });
  }
  send(res, 404, { error: "Not found" });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.url.startsWith("/api/")) return await handleApi(req, res);
    if (req.url === "/" || req.url === "/index.html") {
      // Read the file BEFORE writing headers so a missing file can't crash the server
      const html = fs.readFileSync(INDEX_FILE);
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end(html);
    }
    res.writeHead(404); res.end("Not found");
  } catch (e) {
    console.error(e.message);
    if (!res.headersSent) send(res, 500, { error: "Server error: " + e.message });
    else res.end();
  }
});

// Bind to localhost only: this is a demo, not a hardened service.
server.listen(PORT, "127.0.0.1", () => console.log(`Password manager running at http://localhost:${PORT}`));
module.exports = server;