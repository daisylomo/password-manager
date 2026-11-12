"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

// A password of 64 characters can take up to 4 bytes per character in UTF-8.
// Every record is padded to this fixed size so ciphertext length reveals nothing.
const MAX_PASSWORD_BYTES = MAX_PASSWORD_LENGTH * 4;
const LENGTH_HEADER_BYTES = 2;                         // 2-byte big-endian length prefix
const PADDED_BLOCK_BYTES = LENGTH_HEADER_BYTES + MAX_PASSWORD_BYTES;

const SALT_BYTES = 16;   // 128-bit salt for PBKDF2
const IV_BYTES = 12;     // 96-bit nonce for AES-GCM (recommended size)

// Labels used to derive independent sub-keys from the master key with HMAC (as a PRF)
const DOMAIN_KEY_LABEL = "keychain/domain-name-hmac-key";
const AES_KEY_LABEL = "keychain/aes-gcm-encryption-key";

// Password verification record: AES-GCM encryption of a known constant. The AAD
// ("check") can never collide with a domain tag (a 44-char Base64 string).
const CHECK_PLAINTEXT = "keychain-password-check";
const CHECK_AAD = "check";

/********* Helpers ********/

/** Pads a password to a fixed-size block: [2-byte length][bytes][zero padding]. */
function padPassword(value) {
  if (typeof value !== "string") {
    throw new Error("Value must be a string");
  }
  if (value.length > MAX_PASSWORD_LENGTH) {
    throw new Error("Password exceeds the maximum length of " + MAX_PASSWORD_LENGTH);
  }
  const bytes = stringToBuffer(value);
  if (bytes.length > MAX_PASSWORD_BYTES) {
    throw new Error("Password too long");
  }
  const block = new Uint8Array(PADDED_BLOCK_BYTES); // zero filled
  block[0] = (bytes.length >> 8) & 0xff;
  block[1] = bytes.length & 0xff;
  block.set(bytes, LENGTH_HEADER_BYTES);
  return block;
}

/** Inverse of padPassword. */
function unpadPassword(block) {
  const buf = new Uint8Array(block);
  if (buf.length !== PADDED_BLOCK_BYTES) {
    throw new Error("Tampering detected: malformed record");
  }
  const len = (buf[0] << 8) | buf[1];
  if (len > MAX_PASSWORD_BYTES) {
    throw new Error("Tampering detected: malformed record");
  }
  return bufferToString(buf.slice(LENGTH_HEADER_BYTES, LENGTH_HEADER_BYTES + len));
}

/** Encrypts plaintext bytes with a fresh random IV, binding `aad` as associated data. */
async function encryptRecord(aesKey, plaintextBytes, aad) {
  const iv = getRandomBytes(IV_BYTES);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(aad) },
    aesKey,
    plaintextBytes
  );
  return { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
}

/** Decrypts a record; throws if authentication (including the AAD) fails. */
async function decryptRecord(aesKey, record, aad) {
  if (!record || typeof record.iv !== "string" || typeof record.ct !== "string") {
    throw new Error("Tampering detected: malformed record");
  }
  try {
    return await subtle.decrypt(
      { name: "AES-GCM", iv: decodeBuffer(record.iv), additionalData: stringToBuffer(aad) },
      aesKey,
      decodeBuffer(record.ct)
    );
  } catch (e) {
    throw new Error("Tampering detected or wrong password: authentication failed");
  }
}

/**
 * Runs PBKDF2 exactly once to get the master key k (an HMAC key), then derives
 * two independent sub-keys by evaluating HMAC(k, label).
 */
async function deriveKeys(password, salt) {
  const pwKey = await subtle.importKey(
    "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);

  const masterKey = await subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    pwKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  );

  const domainKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer(DOMAIN_KEY_LABEL));
  const aesKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer(AES_KEY_LABEL));

  const macKey = await subtle.importKey(
    "raw", domainKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const aesKey = await subtle.importKey(
    "raw", aesKeyMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);

  return { macKey, aesKey };
}

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *   salt:   Uint8Array/Buffer, PBKDF2 salt
   *   keys:   { macKey, aesKey } derived CryptoKeys
   *   kvs:    object mapping HMAC(domain) -> { iv, ct }
   *   check:  { iv, ct } password verification record
   * Return Type: void
   */
  constructor(salt, keys, kvs, check) {
    this.data = {
      // public: safe for an adversary to see (this is what gets dumped)
      salt: encodeBuffer(salt),
      check: check,
      kvs: kvs
    };
    this.secrets = {
      // private: never serialized
      macKey: keys.macKey,
      aesKey: keys.aesKey
    };
  };

  /**
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const salt = getRandomBytes(SALT_BYTES);
    const keys = await deriveKeys(password, salt);
    const check = await encryptRecord(keys.aesKey, stringToBuffer(CHECK_PLAINTEXT), CHECK_AAD);
    return new Keychain(salt, keys, {}, check);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    // Rollback defense: verify the checksum over the exact serialized bytes first.
    if (trustedDataCheck !== undefined) {
      const digest = await subtle.digest("SHA-256", stringToBuffer(repr));
      if (encodeBuffer(digest) !== trustedDataCheck) {
        throw new Error("Tampering detected: checksum mismatch");
      }
    }

    const obj = JSON.parse(repr);
    if (!obj || typeof obj.salt !== "string" || typeof obj.kvs !== "object" ||
        obj.kvs === null || !obj.check) {
      throw new Error("Malformed keychain representation");
    }

    const salt = decodeBuffer(obj.salt);
    const keys = await deriveKeys(password, salt);   // the single PBKDF2 call

    // Password verification: the check record only decrypts under the right keys.
    let plain;
    try {
      plain = await decryptRecord(keys.aesKey, obj.check, CHECK_AAD);
    } catch (e) {
      throw new Error("Invalid password or corrupted keychain");
    }
    if (bufferToString(plain) !== CHECK_PLAINTEXT) {
      throw new Error("Invalid password or corrupted keychain");
    }

    return new Keychain(salt, keys, obj.kvs, obj.check);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    const repr = JSON.stringify(this.data);
    const digest = await subtle.digest("SHA-256", stringToBuffer(repr));
    return [repr, encodeBuffer(digest)];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    const tag = await this._domainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return null;
    }
    // Swap defense: the tag (HMAC of the domain) is the AAD, so a record copied
    // under a different key fails authentication.
    const block = await decryptRecord(this.secrets.aesKey, this.data.kvs[tag], tag);
    return unpadPassword(block);
  };

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    const tag = await this._domainTag(name);
    const block = padPassword(value);
    this.data.kvs[tag] = await encryptRecord(this.secrets.aesKey, block, tag);
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    const tag = await this._domainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return false;
    }
    delete this.data.kvs[tag];
    return true;
  };

  /** Returns Base64(HMAC(macKey, name)), the KVS key for a domain. */
  async _domainTag(name) {
    const mac = await subtle.sign("HMAC", this.secrets.macKey, stringToBuffer(name));
    return encodeBuffer(mac);
  }
};

module.exports = { Keychain }