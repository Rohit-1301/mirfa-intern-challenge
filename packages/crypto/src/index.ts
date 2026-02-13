/**
 * @repo/crypto — Shared envelope encryption library
 *
 * Re-exports all public types and functions for consumers.
 */
export { envelopeEncrypt, envelopeDecrypt, validateRecord } from "./envelope.js";
export type { TxSecureRecord, EncryptInput, DecryptResult } from "./types.js";
export { parseMasterKey, validateHex } from "./utils.js";
export { buildKeyRegistry, getLatestVersion, getKey, type KeyRegistry } from "./keys.js";
