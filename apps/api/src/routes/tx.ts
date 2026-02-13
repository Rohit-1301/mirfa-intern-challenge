/**
 * Transaction routes for the Fastify API.
 *
 * POST /tx/encrypt     — Encrypt & store a payload using envelope encryption
 * GET  /tx/:id         — Retrieve an encrypted record by ID
 * POST /tx/:id/decrypt — Decrypt and return the original payload (rate-limited)
 *
 * Storage is an in-memory Map (non-persistent, suitable for demo/dev).
 *
 * Security features:
 *   - Key versioning: supports multiple master keys for rotation
 *   - AAD: partyId is cryptographically bound to ciphertext
 *   - Rate limiting: decrypt endpoint is limited to 5 req/min per IP
 *   - Structured logging: decryption failures are logged with context
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { randomUUID } from "node:crypto";
import {
  envelopeEncrypt,
  envelopeDecrypt,
  buildKeyRegistry,
  type TxSecureRecord,
} from "@repo/crypto";

// In-memory store — records are lost on server restart
const store = new Map<string, TxSecureRecord>();

/**
 * Build the master key registry from environment variables.
 * Supports MASTER_KEY_V1, MASTER_KEY_V2, ... or fallback to MASTER_KEY.
 */
function getKeyRegistry() {
  return buildKeyRegistry(process.env as Record<string, string | undefined>);
}

// ----- Request/Response schemas -----

interface EncryptBody {
  partyId: string;
  payload: Record<string, unknown>;
}

interface IdParam {
  id: string;
}

// ----- Route registration -----

export async function txRoutes(app: FastifyInstance): Promise<void> {
  /**
   * POST /tx/encrypt
   *
   * Accepts a partyId and JSON payload, performs envelope encryption,
   * stores the record, and returns the full TxSecureRecord.
   *
   * Uses the latest master key version for encryption.
   * Binds partyId as AAD (Additional Authenticated Data).
   */
  app.post<{ Body: EncryptBody }>(
    "/tx/encrypt",
    async (request: FastifyRequest<{ Body: EncryptBody }>, reply: FastifyReply) => {
      const { partyId, payload } = request.body;

      // Input validation
      if (!partyId || typeof partyId !== "string" || partyId.trim().length === 0) {
        return reply.status(400).send({ error: "partyId is required and must be a non-empty string" });
      }

      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        return reply.status(400).send({ error: "payload is required and must be a JSON object" });
      }

      try {
        const id = randomUUID();
        const registry = getKeyRegistry();

        // Perform envelope encryption: DEK encrypts payload, MK wraps DEK
        // partyId is bound as AAD to both layers
        const record = envelopeEncrypt(registry, id, partyId.trim(), payload);

        // Store in memory
        store.set(id, record);

        return reply.status(201).send(record);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Encryption failed";
        return reply.status(500).send({ error: message });
      }
    }
  );

  /**
   * GET /tx
   *
   * Lists all stored transaction records (summary only).
   * Returns id, partyId, createdAt, and alg for each record.
   */
  app.get(
    "/tx",
    async (_request, reply) => {
      const records = Array.from(store.values())
        .map(({ id, partyId, createdAt, alg }) => ({ id, partyId, createdAt, alg }))
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

      return reply.send(records);
    }
  );

  /**
   * GET /tx/:id
   *
   * Retrieves the encrypted record by its ID.
   * Returns the full TxSecureRecord (still encrypted).
   */
  app.get<{ Params: IdParam }>(
    "/tx/:id",
    async (request: FastifyRequest<{ Params: IdParam }>, reply: FastifyReply) => {
      const { id } = request.params;

      const record = store.get(id);
      if (!record) {
        return reply.status(404).send({ error: `Record not found: ${id}` });
      }

      return reply.send(record);
    }
  );

  /**
   * POST /tx/:id/decrypt
   *
   * Decrypts the stored record and returns the original payload.
   * This unwraps the DEK using the Master Key, then decrypts the payload with the DEK.
   *
   * Security:
   *   - Rate limited: max 5 requests per minute per IP
   *   - Structured logging on failure (txId, IP, mk_version, timestamp)
   *   - Sensitive payloads are NEVER logged
   */
  app.post<{ Params: IdParam }>(
    "/tx/:id/decrypt",
    {
      config: {
        rateLimit: {
          max: 5,
          timeWindow: "1 minute",
        },
      },
    },
    async (request: FastifyRequest<{ Params: IdParam }>, reply: FastifyReply) => {
      const { id } = request.params;

      const record = store.get(id);
      if (!record) {
        return reply.status(404).send({ error: `Record not found: ${id}` });
      }

      try {
        const registry = getKeyRegistry();

        // Envelope decryption: unwrap DEK with MK, then decrypt payload with DEK
        // AAD (partyId) is verified during both decryption steps
        const payload = envelopeDecrypt(registry, record);

        return reply.send({
          id: record.id,
          partyId: record.partyId,
          payload,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : "Decryption failed";

        // Structured security logging — log context for audit, NEVER log payloads
        request.log.warn(
          {
            event: "decryption_failure",
            txId: id,
            ip: request.ip,
            mk_version: record.mk_version,
            timestamp: new Date().toISOString(),
            error: message,
          },
          "Decryption failed for transaction"
        );

        return reply.status(500).send({ error: message });
      }
    }
  );
}
