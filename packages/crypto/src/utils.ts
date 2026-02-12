/**
 * Utility helpers for hex encoding/decoding and input validation.
 * All crypto values are stored as hex strings to ensure safe JSON transport.
 */
import { Buffer } from "node:buffer";

/**
 * Validates that a string is valid hexadecimal and optionally checks byte length.
 * @throws Error if the string is not valid hex or does not match expected byte length.
 */
export function validateHex(value: string, label: string, expectedBytes?: number): Buffer {
  // Hex strings must have even length and contain only hex characters
  if (!/^[0-9a-f]*$/i.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label}: invalid hex encoding`);
  }

  const buf = Buffer.from(value, "hex");

  if (expectedBytes !== undefined && buf.length !== expectedBytes) {
    throw new Error(
      `${label}: expected ${expectedBytes} bytes, got ${buf.length} bytes`
    );
  }

  return buf;
}

/**
 * Validates the Master Key is exactly 32 bytes (64 hex characters).
 * @returns Buffer containing the decoded master key.
 */
export function parseMasterKey(hexKey: string): Buffer {
  if (!hexKey) {
    throw new Error("MASTER_KEY environment variable is required");
  }
  return validateHex(hexKey, "MASTER_KEY", 32);
}
