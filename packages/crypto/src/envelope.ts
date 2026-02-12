/**
 * Envelope Encryption using AES-256-GCM
 * ========================================
 *
 * Envelope encryption is a two-layer encryption strategy:
 *
 * Layer 1 — Data Encryption:
 *   - A fresh random Data Encryption Key (DEK) is generated per record.
 *   - The plaintext payload is encrypted with AES-256-GCM using the DEK.
 *   - This produces: ciphertext + nonce + authentication tag.
 *
 * Layer 2 — Key Wrapping:
 *   - The DEK itself is encrypted ("wrapped") using the Master Key (MK).
 *   - This produces: wrapped DEK + nonce + authentication tag.
 *
 * Benefits:
 *   - The Master Key never directly touches user data.
 *   - Key rotation only requires re-wrapping DEKs, not re-encrypting data.
 *   - Each record uses a unique DEK, limiting blast radius of key compromise.
 *
 * AES-256-GCM specifics:
 *   - 256-bit (32-byte) key
 *   - 96-bit (12-byte) nonce/IV (NIST recommended for GCM)
 *   - 128-bit (16-byte) authentication tag (provides integrity + authenticity)
 */

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { Buffer } from "node:buffer";
import type { TxSecureRecord } from "./types.js";
import { validateHex, parseMasterKey } from "./utils.js";

// ----- Constants -----

const ALGORITHM = "aes-256-gcm" as const;
const DEK_BYTES = 32;    // 256-bit DEK
const NONCE_BYTES = 12;  // 96-bit nonce (NIST recommendation for GCM)
const TAG_BYTES = 16;    // 128-bit auth tag

// ----- Low-level helpers -----

interface EncryptResult {
  nonce: string;  // hex
  ct: string;     // hex
  tag: string;    // hex
}

/**
 * Encrypt plaintext bytes with AES-256-GCM.
 * Generates a cryptographically random 12-byte nonce per call.
 *
 * @param key  - 32-byte encryption key
 * @param data - plaintext buffer to encrypt
 * @returns nonce, ciphertext, and auth tag as hex strings
 */
function aesGcmEncrypt(key: Buffer, data: Buffer): EncryptResult {
  // Generate a fresh random nonce for each encryption operation.
  // Nonce reuse with the same key completely breaks GCM security.
  const nonce = randomBytes(NONCE_BYTES);

  const cipher = createCipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_BYTES,
  });

  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    nonce: nonce.toString("hex"),
    ct: ct.toString("hex"),
    tag: tag.toString("hex"),
  };
}

/**
 * Decrypt ciphertext with AES-256-GCM.
 * Validates nonce length, tag length, and hex encoding before attempting decryption.
 * Throws on any integrity failure (tampered ciphertext, wrong key, wrong tag).
 *
 * @param key      - 32-byte decryption key
 * @param nonceHex - 12-byte nonce as hex
 * @param ctHex    - ciphertext as hex
 * @param tagHex   - 16-byte auth tag as hex
 * @returns decrypted plaintext buffer
 */
function aesGcmDecrypt(
  key: Buffer,
  nonceHex: string,
  ctHex: string,
  tagHex: string
): Buffer {
  // Validate all inputs before decryption
  const nonce = validateHex(nonceHex, "nonce", NONCE_BYTES);
  const ct = validateHex(ctHex, "ciphertext");
  const tag = validateHex(tagHex, "auth_tag", TAG_BYTES);

  const decipher = createDecipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_BYTES,
  });

  // Set the authentication tag BEFORE calling update/final.
  // If the tag doesn't match, final() will throw.
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (err) {
    // GCM authentication failure — ciphertext or tag has been tampered with
    throw new Error(
      `Decryption failed: authentication tag mismatch (data may be tampered). ${err instanceof Error ? err.message : ""}`
    );
  }
}

// ----- Public API -----

/**
 * Encrypt a payload using envelope encryption.
 *
 * Steps:
 *   1. Generate a random 32-byte Data Encryption Key (DEK)
 *   2. Encrypt the JSON payload with the DEK (AES-256-GCM)
 *   3. Wrap (encrypt) the DEK with the Master Key (AES-256-GCM)
 *   4. Return a TxSecureRecord containing all encrypted components
 *
 * @param masterKeyHex - 32-byte master key as hex string
 * @param id           - unique record identifier
 * @param partyId      - party/entity identifier
 * @param payload      - JSON-serializable payload to encrypt
 * @returns TxSecureRecord with all fields populated
 */
export function envelopeEncrypt(
  masterKeyHex: string,
  id: string,
  partyId: string,
  payload: Record<string, unknown>
): TxSecureRecord {
  const masterKey = parseMasterKey(masterKeyHex);

  // Step 1: Generate a fresh random DEK for this record
  const dek = randomBytes(DEK_BYTES);

  // Step 2: Encrypt payload with DEK
  const plaintext = Buffer.from(JSON.stringify(payload), "utf-8");
  const payloadEnc = aesGcmEncrypt(dek, plaintext);

  // Step 3: Wrap DEK with Master Key
  const dekEnc = aesGcmEncrypt(masterKey, dek);

  // Step 4: Assemble the secure record
  return {
    id,
    partyId,
    createdAt: new Date().toISOString(),

    payload_nonce: payloadEnc.nonce,
    payload_ct: payloadEnc.ct,
    payload_tag: payloadEnc.tag,

    dek_wrap_nonce: dekEnc.nonce,
    dek_wrapped: dekEnc.ct,
    dek_wrap_tag: dekEnc.tag,

    alg: "AES-256-GCM",
    mk_version: 1,
  };
}

/**
 * Decrypt a TxSecureRecord using envelope decryption.
 *
 * Steps:
 *   1. Unwrap the DEK using the Master Key (AES-256-GCM decrypt)
 *   2. Decrypt the payload using the recovered DEK (AES-256-GCM decrypt)
 *   3. Parse and return the original JSON payload
 *
 * @param masterKeyHex - 32-byte master key as hex string
 * @param record       - the encrypted TxSecureRecord
 * @returns the original JSON payload
 * @throws on tampered data, invalid hex, wrong key, or parse errors
 */
export function envelopeDecrypt(
  masterKeyHex: string,
  record: TxSecureRecord
): Record<string, unknown> {
  const masterKey = parseMasterKey(masterKeyHex);

  // Step 1: Unwrap the DEK using the Master Key
  const dek = aesGcmDecrypt(
    masterKey,
    record.dek_wrap_nonce,
    record.dek_wrapped,
    record.dek_wrap_tag
  );

  // Step 2: Decrypt payload using the recovered DEK
  const plaintext = aesGcmDecrypt(
    dek,
    record.payload_nonce,
    record.payload_ct,
    record.payload_tag
  );

  // Step 3: Parse JSON payload
  try {
    return JSON.parse(plaintext.toString("utf-8")) as Record<string, unknown>;
  } catch {
    throw new Error("Decryption produced invalid JSON — possible data corruption");
  }
}
