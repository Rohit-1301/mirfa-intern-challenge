/**
 * Transaction routes for the Fastify API.
 *
 * POST /tx/encrypt  — Encrypt & store a payload using envelope encryption
 * GET  /tx/:id      — Retrieve an encrypted record by ID
 * POST /tx/:id/decrypt — Decrypt and return the original payload
 *
 * Storage is an in-memory Map (non-persistent, suitable for demo/dev).
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { randomUUID } from "node:crypto";
import {
  envelopeEncrypt,
  envelopeDecrypt,
  type TxSecureRecord,
  type EncryptInput,
} from "@repo/crypto";

// In-memory store — records are lost on server restart
const store = new Map<string, TxSecureRecord>();

/**
 * Get the MASTER_KEY from environment, throw if missing.
 */
function getMasterKey(): string {
  const key = process.env.MASTER_KEY;
  if (!key) {
    throw new Error("MASTER_KEY environment variable is not set");
  }
  return key;
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
        const masterKey = getMasterKey();

        // Perform envelope encryption: DEK encrypts payload, MK wraps DEK
        const record = envelopeEncrypt(masterKey, id, partyId.trim(), payload);

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
   */
  app.post<{ Params: IdParam }>(
    "/tx/:id/decrypt",
    async (request: FastifyRequest<{ Params: IdParam }>, reply: FastifyReply) => {
      const { id } = request.params;

      const record = store.get(id);
      if (!record) {
        return reply.status(404).send({ error: `Record not found: ${id}` });
      }

      try {
        const masterKey = getMasterKey();

        // Envelope decryption: unwrap DEK with MK, then decrypt payload with DEK
        const payload = envelopeDecrypt(masterKey, record);

        return reply.send({
          id: record.id,
          partyId: record.partyId,
          payload,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : "Decryption failed";
        return reply.status(500).send({ error: message });
      }
    }
  );
}
