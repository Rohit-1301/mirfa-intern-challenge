/**
 * Master Key Registry — Key Rotation Support
 * =============================================
 *
 * Manages multiple master key versions for key rotation.
 *
 * Key rotation allows replacing the master key without re-encrypting
 * existing data. Each record stores the mk_version it was encrypted with,
 * so decryption always uses the correct key.
 *
 * Environment variables:
 *   MASTER_KEY_V1=<64 hex chars>
 *   MASTER_KEY_V2=<64 hex chars>  (optional, for rotation)
 *   MASTER_KEY_V3=...             (optional)
 *
 * Backward compatibility:
 *   If only MASTER_KEY is set (no versioned keys), it is treated as V1.
 */

import { Buffer } from "node:buffer";
import { validateHex } from "./utils.js";

/** Immutable map of version numbers to decoded master key buffers */
export type KeyRegistry = Readonly<Record<number, Buffer>>;

/**
 * Build a key registry from environment variables.
 *
 * Scans for MASTER_KEY_V1, MASTER_KEY_V2, ... and validates each
 * as a 32-byte (64 hex char) AES-256 key.
 *
 * Falls back to MASTER_KEY (unversioned) as version 1 for backward compatibility.
 *
 * @param env - process.env or equivalent key-value map
 * @returns KeyRegistry mapping version numbers to decoded key buffers
 * @throws if no master keys are found or any key is invalid
 */
export function buildKeyRegistry(env: Record<string, string | undefined>): KeyRegistry {
  const registry: Record<number, Buffer> = {};

  // Scan for versioned keys: MASTER_KEY_V1, MASTER_KEY_V2, ...
  for (const [key, value] of Object.entries(env)) {
    const match = key.match(/^MASTER_KEY_V(\d+)$/);
    if (match && value) {
      const version = parseInt(match[1], 10);
      registry[version] = validateHex(value, `MASTER_KEY_V${version}`, 32);
    }
  }

  // Backward compatibility: fall back to MASTER_KEY as V1
  if (Object.keys(registry).length === 0 && env.MASTER_KEY) {
    registry[1] = validateHex(env.MASTER_KEY, "MASTER_KEY", 32);
  }

  if (Object.keys(registry).length === 0) {
    throw new Error(
      "No master keys found. Set MASTER_KEY_V1 (or MASTER_KEY) environment variable."
    );
  }

  return Object.freeze(registry);
}

/**
 * Get the highest available master key version.
 * New encryptions always use the latest key.
 */
export function getLatestVersion(registry: KeyRegistry): number {
  const versions = Object.keys(registry).map(Number);
  return Math.max(...versions);
}

/**
 * Get a master key by version number.
 * Used during decryption to look up the key that was used for wrapping.
 *
 * @throws if the requested version is not in the registry
 */
export function getKey(registry: KeyRegistry, version: number): Buffer {
  const key = registry[version];
  if (!key) {
    throw new Error(
      `Master key version ${version} not found. Available versions: ${Object.keys(registry).join(", ")}`
    );
  }
  return key;
}
