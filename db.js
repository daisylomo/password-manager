"use strict";
// SQLite storage for the keychain (uses Node's built-in node:sqlite, so no npm install).
// Only ciphertext is stored: the salt, the password-check record, and one row per
// entry keyed by HMAC(domain). No plaintext domains or passwords ever reach the database.
const { DatabaseSync } = require("node:sqlite");
const path = require("path");

const db = new DatabaseSync(process.env.VAULT_DB || path.join(__dirname, "vault.db"));
db.exec(`
  CREATE TABLE IF NOT EXISTS meta (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    salt     TEXT NOT NULL,
    check_iv TEXT NOT NULL,
    check_ct TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS records (
    seq INTEGER PRIMARY KEY,      -- position in the keychain's kvs, so the dump is reproduced exactly
    tag TEXT NOT NULL UNIQUE,     -- Base64(HMAC(domainKey, domain))
    iv  TEXT NOT NULL,
    ct  TEXT NOT NULL
  );
`);

function exists() {
  return db.prepare("SELECT COUNT(*) AS n FROM meta").get().n > 0;
}

/** Replaces the stored vault with the contents of a dump() string, in one transaction. */
function save(repr) {
  const d = JSON.parse(repr);
  db.exec("BEGIN");
  try {
    db.prepare("INSERT OR REPLACE INTO meta (id, salt, check_iv, check_ct) VALUES (1, ?, ?, ?)")
      .run(d.salt, d.check.iv, d.check.ct);
    db.exec("DELETE FROM records");
    const ins = db.prepare("INSERT INTO records (seq, tag, iv, ct) VALUES (?, ?, ?, ?)");
    let seq = 0;
    for (const [tag, rec] of Object.entries(d.kvs)) ins.run(seq++, tag, rec.iv, rec.ct);
    db.exec("COMMIT");
  } catch (e) { db.exec("ROLLBACK"); throw e; }
}

/** Rebuilds the exact serialization that dump() produced, for Keychain.load. */
function loadRepr() {
  const m = db.prepare("SELECT salt, check_iv, check_ct FROM meta WHERE id = 1").get();
  if (!m) return null;
  const kvs = {};
  for (const r of db.prepare("SELECT tag, iv, ct FROM records ORDER BY seq").all()) {
    kvs[r.tag] = { iv: r.iv, ct: r.ct };
  }
  return JSON.stringify({ salt: m.salt, check: { iv: m.check_iv, ct: m.check_ct }, kvs });
}

module.exports = { exists, save, loadRepr };