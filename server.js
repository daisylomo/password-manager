"use strict";
// Backend: a small HTTP API (no dependencies) around the Keychain library.
// The encrypted vault is persisted to vault.json; the SHA-256 checksum goes in a
// separate file (vault.hash) standing in for the "trusted storage" from the handout.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Keychain } = require("./password-manager");

const PORT = process.env.PORT || 3000;
const VAULT_FILE = path.join(__dirname, "vault.json");
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
  fs.writeFileSync(VAULT_FILE, repr);
  fs.writeFileSync(HASH_FILE, hash);
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
    return send(res, 200, { vaultExists: fs.existsSync(VAULT_FILE), unlocked: authorized(req) });
  }
  if (url === "/api/create") {
    if (fs.existsSync(VAULT_FILE)) return send(res, 409, { error: "Vault already exists" });
    if (!body.password) return send(res, 400, { error: "Password required" });
    keychain = await Keychain.init(body.password);
    await persist();
    sessionToken = crypto.randomBytes(32).toString("hex");
    return send(res, 200, { token: sessionToken });
  }
  if (url === "/api/unlock") {
    if (!fs.existsSync(VAULT_FILE)) return send(res, 404, { error: "No vault" });
    try {
      const repr = fs.readFileSync(VAULT_FILE, "utf8");
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
  if (url === "/api/get") {
    try {
      const value = await keychain.get(String(body.name));
      return send(res, 200, { value });
    } catch (e) { return send(res, 422, { error: "Tampering detected: " + e.message }); }
  }
  if (url === "/api/set") {
    try {
      await keychain.set(String(body.name), String(body.value));
      await persist();
      return send(res, 200, {});
    } catch (e) { return send(res, 400, { error: e.message }); }
  }
  if (url === "/api/remove") {
    const removed = await keychain.remove(String(body.name));
    if (removed) await persist();
    return send(res, 200, { removed });
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