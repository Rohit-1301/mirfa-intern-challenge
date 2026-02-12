/**
 * TxSecureRecord — the envelope-encrypted transaction record.
 *
 * All binary values (nonces, ciphertext, auth tags, wrapped DEK)
 * are stored as lowercase hex strings for safe JSON serialization.
 */
export type TxSecureRecord = {
  /** Unique identifier for this encrypted record */
  id: string;

  /** Identifier for the party/entity that owns this record */
  partyId: string;

  /** ISO-8601 timestamp of record creation */
  createdAt: string;

  // --- Payload encryption (DEK → plaintext) ---

  /** 12-byte nonce used for payload encryption, hex-encoded (24 chars) */
  payload_nonce: string;

  /** AES-256-GCM ciphertext of the JSON payload, hex-encoded */
  payload_ct: string;

  /** 16-byte authentication tag from payload encryption, hex-encoded (32 chars) */
  payload_tag: string;

  // --- DEK wrapping (Master Key → DEK) ---

  /** 12-byte nonce used for DEK wrapping, hex-encoded (24 chars) */
  dek_wrap_nonce: string;

  /** Wrapped (encrypted) DEK, hex-encoded */
  dek_wrapped: string;

  /** 16-byte authentication tag from DEK wrapping, hex-encoded (32 chars) */
  dek_wrap_tag: string;

  // --- Algorithm metadata ---

  /** Encryption algorithm identifier */
  alg: "AES-256-GCM";

  /** Master key version used for wrapping */
  mk_version: 1;
};

/** Input for the encrypt operation */
export interface EncryptInput {
  partyId: string;
  payload: Record<string, unknown>;
}

/** Result of a successful decryption */
export interface DecryptResult {
  id: string;
  partyId: string;
  payload: Record<string, unknown>;
}
