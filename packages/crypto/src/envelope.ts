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
 * AAD (Additional Authenticated Data):
 *   - partyId is bound as AAD to both the payload encryption and DEK wrapping.
 *   - AAD is NOT encrypted, but it IS authenticated — if anyone modifies the
 *     partyId on a stored record, decryption will fail with an auth tag mismatch.
 *   - This prevents an attacker from re-associating encrypted data to a
 *     different party without detection.
 *
 * Key Rotation:
 *   - Multiple master keys can coexist (V1, V2, ...).
 *   - Encryption always uses the latest version.
 *   - Decryption looks up the key by the record's mk_version field.
 *   - Old records continue to decrypt with their original key.
 *
 * AES-256-GCM specifics:
 *   - 256-bit (32-byte) key
 *   - 96-bit (12-byte) nonce/IV (NIST recommended for GCM)
 *   - 128-bit (16-byte) authentication tag (provides integrity + authenticity)
 */

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { Buffer } from "node:buffer";
import type { TxSecureRecord } from "./types.js";
import { validateHex } from "./utils.js";
import { type KeyRegistry, getLatestVersion, getKey } from "./keys.js";

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
 * @param aad  - optional Additional Authenticated Data (authenticated but not encrypted)
 * @returns nonce, ciphertext, and auth tag as hex strings
 */
function aesGcmEncrypt(key: Buffer, data: Buffer, aad?: Buffer): EncryptResult {
  // Generate a fresh random nonce for each encryption operation.
  // Nonce reuse with the same key completely breaks GCM security.
  const nonce = randomBytes(NONCE_BYTES);

  const cipher = createCipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_BYTES,
  });

  // AAD binds contextual data (e.g. partyId) to the ciphertext.
  // If AAD is modified after encryption, the auth tag won't match during decryption.
  if (aad) {
    cipher.setAAD(aad);
  }

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
 * Throws on any integrity failure (tampered ciphertext, wrong key, wrong tag, wrong AAD).
 *
 * @param key      - 32-byte decryption key
 * @param nonceHex - 12-byte nonce as hex
 * @param ctHex    - ciphertext as hex
 * @param tagHex   - 16-byte auth tag as hex
 * @param aad      - optional AAD that must match what was used during encryption
 * @returns decrypted plaintext buffer
 */
function aesGcmDecrypt(
  key: Buffer,
  nonceHex: string,
  ctHex: string,
  tagHex: string,
  aad?: Buffer
): Buffer {
  // Validate all inputs before decryption
  const nonce = validateHex(nonceHex, "nonce", NONCE_BYTES);
  const ct = validateHex(ctHex, "ciphertext");
  const tag = validateHex(tagHex, "auth_tag", TAG_BYTES);

  const decipher = createDecipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_BYTES,
  });

  // AAD must exactly match what was provided during encryption.
  // Mismatched AAD causes GCM authentication to fail.
  if (aad) {
    decipher.setAAD(aad);
  }

  // Set the authentication tag BEFORE calling update/final.
  // If the tag doesn't match, final() will throw.
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (err) {
    // GCM authentication failure — ciphertext, tag, or AAD has been tampered with
    throw new Error(
      `Decryption failed: authentication tag mismatch (data may be tampered). ${err instanceof Error ? err.message : ""}`
    );
  }
}

// ----- Record Validation -----

/**
 * Validate all hex fields on a TxSecureRecord before attempting decryption.
 * This provides early, descriptive errors instead of cryptic crypto failures.
 *
 * @throws on any invalid hex field, wrong nonce length, or wrong tag length
 */
export function validateRecord(record: TxSecureRecord): void {
  validateHex(record.payload_nonce, "payload_nonce", NONCE_BYTES);
  validateHex(record.payload_ct, "payload_ct");
  validateHex(record.payload_tag, "payload_tag", TAG_BYTES);
  validateHex(record.dek_wrap_nonce, "dek_wrap_nonce", NONCE_BYTES);
  validateHex(record.dek_wrapped, "dek_wrapped");
  validateHex(record.dek_wrap_tag, "dek_wrap_tag", TAG_BYTES);
}

// ----- Public API -----

/**
 * Encrypt a payload using envelope encryption with key versioning and AAD.
 *
 * Steps:
 *   1. Look up the latest master key version from the registry
 *   2. Generate a random 32-byte Data Encryption Key (DEK)
 *   3. Encrypt the JSON payload with the DEK (AES-256-GCM), using partyId as AAD
 *   4. Wrap (encrypt) the DEK with the Master Key (AES-256-GCM), using partyId as AAD
 *   5. Return a TxSecureRecord containing all encrypted components
 *
 * @param registry - master key registry (version → key buffer)
 * @param id       - unique record identifier
 * @param partyId  - party/entity identifier (also used as AAD)
 * @param payload  - JSON-serializable payload to encrypt
 * @returns TxSecureRecord with all fields populated
 */
export function envelopeEncrypt(
  registry: KeyRegistry,
  id: string,
  partyId: string,
  payload: Record<string, unknown>
): TxSecureRecord {
  // Step 1: Use the latest master key version for new encryptions
  const mkVersion = getLatestVersion(registry);
  const masterKey = getKey(registry, mkVersion);

  // AAD: partyId is cryptographically bound to the ciphertext.
  // This prevents re-associating encrypted data to a different party.
  const aad = Buffer.from(partyId, "utf-8");

  // Step 2: Generate a fresh random DEK for this record
  const dek = randomBytes(DEK_BYTES);

  // Step 3: Encrypt payload with DEK, binding partyId as AAD
  const plaintext = Buffer.from(JSON.stringify(payload), "utf-8");
  const payloadEnc = aesGcmEncrypt(dek, plaintext, aad);

  // Step 4: Wrap DEK with Master Key, also binding partyId as AAD
  const dekEnc = aesGcmEncrypt(masterKey, dek, aad);

  // Step 5: Assemble the secure record
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
    mk_version: mkVersion,
  };
}

/**
 * Decrypt a TxSecureRecord using envelope decryption with key versioning and AAD.
 *
 * Steps:
 *   1. Validate all hex fields on the record
 *   2. Look up the master key by the record's mk_version
 *   3. Unwrap the DEK using the Master Key (AES-256-GCM decrypt), verifying partyId AAD
 *   4. Decrypt the payload using the recovered DEK (AES-256-GCM decrypt), verifying partyId AAD
 *   5. Parse and return the original JSON payload
 *
 * @param registry - master key registry (version → key buffer)
 * @param record   - the encrypted TxSecureRecord
 * @returns the original JSON payload
 * @throws on tampered data, invalid hex, wrong key version, AAD mismatch, or parse errors
 */
export function envelopeDecrypt(
  registry: KeyRegistry,
  record: TxSecureRecord
): Record<string, unknown> {
  // Step 1: Validate all hex fields before any crypto operations
  validateRecord(record);

  // Step 2: Look up the master key used when this record was encrypted
  const masterKey = getKey(registry, record.mk_version);

  // AAD must match what was used during encryption
  const aad = Buffer.from(record.partyId, "utf-8");

  // Step 3: Unwrap the DEK using the Master Key, with partyId as AAD
  const dek = aesGcmDecrypt(
    masterKey,
    record.dek_wrap_nonce,
    record.dek_wrapped,
    record.dek_wrap_tag,
    aad
  );

  // Step 4: Decrypt payload using the recovered DEK, with partyId as AAD
  const plaintext = aesGcmDecrypt(
    dek,
    record.payload_nonce,
    record.payload_ct,
    record.payload_tag,
    aad
  );

  // Step 5: Parse JSON payload
  try {
    return JSON.parse(plaintext.toString("utf-8")) as Record<string, unknown>;
  } catch {
    throw new Error("Decryption produced invalid JSON — possible data corruption");
  }
}
