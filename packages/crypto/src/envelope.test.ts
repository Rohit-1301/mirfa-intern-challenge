/**
 * Security Tests for Envelope Encryption
 * ========================================
 *
 * Tests cover:
 *   1. Encrypt → decrypt round-trip succeeds
 *   2. Tampered ciphertext → decryption fails
 *   3. Tampered auth tag → decryption fails
 *   4. Wrong master key version → decryption fails
 *   5. Modified partyId → decryption fails (AAD mismatch)
 *   6. Key registry backward compatibility
 *
 * Uses Node's built-in test runner (node:test).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  envelopeEncrypt,
  envelopeDecrypt,
  buildKeyRegistry,
  type KeyRegistry,
  type TxSecureRecord,
} from "./index.js";

// ----- Test helpers -----

/** Generate a random 32-byte hex key */
function randomKeyHex(): string {
  return randomBytes(32).toString("hex");
}

/** Build a single-key registry for testing */
function singleKeyRegistry(keyHex: string): KeyRegistry {
  return buildKeyRegistry({ MASTER_KEY_V1: keyHex });
}

/** Deep clone a record so mutations don't affect the original */
function cloneRecord(record: TxSecureRecord): TxSecureRecord {
  return JSON.parse(JSON.stringify(record));
}

// ----- Test data -----

const TEST_KEY_V1 = randomKeyHex();
const TEST_KEY_V2 = randomKeyHex();
const TEST_PARTY_ID = "test-party-42";
const TEST_PAYLOAD = { amount: 1500, currency: "USD", merchant: "Acme Corp" };

// ----- Tests -----

describe("Envelope Encryption", () => {
  it("should encrypt and decrypt a payload successfully (round-trip)", () => {
    const registry = singleKeyRegistry(TEST_KEY_V1);

    const record = envelopeEncrypt(registry, "tx-001", TEST_PARTY_ID, TEST_PAYLOAD);

    // Verify record structure
    assert.equal(record.id, "tx-001");
    assert.equal(record.partyId, TEST_PARTY_ID);
    assert.equal(record.alg, "AES-256-GCM");
    assert.equal(record.mk_version, 1);
    assert.equal(record.payload_nonce.length, 24); // 12 bytes = 24 hex chars
    assert.equal(record.payload_tag.length, 32);   // 16 bytes = 32 hex chars
    assert.equal(record.dek_wrap_nonce.length, 24);
    assert.equal(record.dek_wrap_tag.length, 32);

    // Decrypt and verify payload
    const decrypted = envelopeDecrypt(registry, record);
    assert.deepEqual(decrypted, TEST_PAYLOAD);
  });

  it("should fail when ciphertext is tampered with", () => {
    const registry = singleKeyRegistry(TEST_KEY_V1);
    const record = envelopeEncrypt(registry, "tx-002", TEST_PARTY_ID, TEST_PAYLOAD);

    // Tamper with the payload ciphertext — flip a character
    const tampered = cloneRecord(record);
    const chars = tampered.payload_ct.split("");
    chars[0] = chars[0] === "a" ? "b" : "a";
    tampered.payload_ct = chars.join("");

    assert.throws(
      () => envelopeDecrypt(registry, tampered),
      /Decryption failed|authentication tag mismatch/
    );
  });

  it("should fail when auth tag is tampered with", () => {
    const registry = singleKeyRegistry(TEST_KEY_V1);
    const record = envelopeEncrypt(registry, "tx-003", TEST_PARTY_ID, TEST_PAYLOAD);

    // Tamper with the payload auth tag
    const tampered = cloneRecord(record);
    const chars = tampered.payload_tag.split("");
    chars[0] = chars[0] === "a" ? "b" : "a";
    tampered.payload_tag = chars.join("");

    assert.throws(
      () => envelopeDecrypt(registry, tampered),
      /Decryption failed|authentication tag mismatch/
    );
  });

  it("should fail when wrong master key version is used", () => {
    // Encrypt with V1
    const registryV1 = singleKeyRegistry(TEST_KEY_V1);
    const record = envelopeEncrypt(registryV1, "tx-004", TEST_PARTY_ID, TEST_PAYLOAD);

    // Try to decrypt with a different key (V2 only, no V1)
    const registryV2Only = buildKeyRegistry({ MASTER_KEY_V2: TEST_KEY_V2 });

    assert.throws(
      () => envelopeDecrypt(registryV2Only, record),
      /Master key version 1 not found/
    );
  });

  it("should fail when partyId is modified (AAD mismatch)", () => {
    const registry = singleKeyRegistry(TEST_KEY_V1);
    const record = envelopeEncrypt(registry, "tx-005", TEST_PARTY_ID, TEST_PAYLOAD);

    // Modify partyId — this should break AAD verification
    const tampered = cloneRecord(record);
    tampered.partyId = "attacker-party-99";

    assert.throws(
      () => envelopeDecrypt(registry, tampered),
      /Decryption failed|authentication tag mismatch/
    );
  });

  it("should support key rotation (encrypt with V2, decrypt V1 and V2 records)", () => {
    // Registry with both keys
    const multiRegistry = buildKeyRegistry({
      MASTER_KEY_V1: TEST_KEY_V1,
      MASTER_KEY_V2: TEST_KEY_V2,
    });

    // Encrypt with V1-only registry
    const registryV1 = singleKeyRegistry(TEST_KEY_V1);
    const recordV1 = envelopeEncrypt(registryV1, "tx-006a", TEST_PARTY_ID, TEST_PAYLOAD);
    assert.equal(recordV1.mk_version, 1);

    // Encrypt with multi-key registry — should use V2 (latest)
    const recordV2 = envelopeEncrypt(multiRegistry, "tx-006b", TEST_PARTY_ID, TEST_PAYLOAD);
    assert.equal(recordV2.mk_version, 2);

    // Multi-registry can decrypt BOTH versions
    assert.deepEqual(envelopeDecrypt(multiRegistry, recordV1), TEST_PAYLOAD);
    assert.deepEqual(envelopeDecrypt(multiRegistry, recordV2), TEST_PAYLOAD);
  });

  it("should support backward compatibility with MASTER_KEY env var", () => {
    const key = randomKeyHex();
    const registry = buildKeyRegistry({ MASTER_KEY: key });

    const record = envelopeEncrypt(registry, "tx-007", TEST_PARTY_ID, TEST_PAYLOAD);
    assert.equal(record.mk_version, 1);

    const decrypted = envelopeDecrypt(registry, record);
    assert.deepEqual(decrypted, TEST_PAYLOAD);
  });

  it("should fail when nonce length is wrong (not 12 bytes)", () => {
    const registry = singleKeyRegistry(TEST_KEY_V1);
    const record = envelopeEncrypt(registry, "tx-008", TEST_PARTY_ID, TEST_PAYLOAD);

    // Wrong payload_nonce length (8 bytes instead of 12)
    const tamperedPayloadNonce = cloneRecord(record);
    tamperedPayloadNonce.payload_nonce = randomBytes(8).toString("hex");

    assert.throws(
      () => envelopeDecrypt(registry, tamperedPayloadNonce),
      /expected 12 bytes, got 8 bytes/
    );

    // Wrong dek_wrap_nonce length (16 bytes instead of 12)
    const tamperedDekNonce = cloneRecord(record);
    tamperedDekNonce.dek_wrap_nonce = randomBytes(16).toString("hex");

    assert.throws(
      () => envelopeDecrypt(registry, tamperedDekNonce),
      /expected 12 bytes, got 16 bytes/
    );
  });
});
