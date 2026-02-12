"use client";

import { useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

export default function Home() {
  // ----- Form state -----
  const [partyId, setPartyId] = useState("");
  const [payloadText, setPayloadText] = useState('{\n  "amount": 1500,\n  "currency": "USD",\n  "merchant": "Acme Corp"\n}');
  const [recordId, setRecordId] = useState("");

  // ----- Output state -----
  const [encryptedRecord, setEncryptedRecord] = useState<object | null>(null);
  const [decryptedResult, setDecryptedResult] = useState<object | null>(null);
  const [status, setStatus] = useState<{ type: "error" | "success"; msg: string } | null>(null);
  const [loading, setLoading] = useState(false);

  // ----- Helpers -----

  function showError(msg: string) {
    setStatus({ type: "error", msg });
  }

  function showSuccess(msg: string) {
    setStatus({ type: "success", msg });
  }

  // ----- Encrypt & Save -----
  async function handleEncrypt() {
    setStatus(null);
    setDecryptedResult(null);

    if (!partyId.trim()) {
      return showError("Party ID is required");
    }

    let payload: object;
    try {
      payload = JSON.parse(payloadText);
      if (typeof payload !== "object" || Array.isArray(payload) || payload === null) {
        throw new Error();
      }
    } catch {
      return showError("Payload must be a valid JSON object");
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/tx/encrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ partyId: partyId.trim(), payload }),
      });

      const data = await res.json();

      if (!res.ok) {
        return showError(data.error || "Encryption failed");
      }

      setEncryptedRecord(data);
      setRecordId(data.id);
      showSuccess(`Encrypted & saved — ID: ${data.id}`);
    } catch (err) {
      showError(`Network error: ${err instanceof Error ? err.message : "unknown"}`);
    } finally {
      setLoading(false);
    }
  }

  // ----- Fetch Record -----
  async function handleFetch() {
    setStatus(null);
    setDecryptedResult(null);

    if (!recordId.trim()) {
      return showError("Record ID is required");
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/tx/${recordId.trim()}`);
      const data = await res.json();

      if (!res.ok) {
        return showError(data.error || "Fetch failed");
      }

      setEncryptedRecord(data);
      showSuccess("Record fetched successfully");
    } catch (err) {
      showError(`Network error: ${err instanceof Error ? err.message : "unknown"}`);
    } finally {
      setLoading(false);
    }
  }

  // ----- Decrypt -----
  async function handleDecrypt() {
    setStatus(null);

    if (!recordId.trim()) {
      return showError("Record ID is required");
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/tx/${recordId.trim()}/decrypt`, {
        method: "POST",
      });
      const data = await res.json();

      if (!res.ok) {
        return showError(data.error || "Decryption failed");
      }

      setDecryptedResult(data);
      showSuccess("Decrypted successfully");
    } catch (err) {
      showError(`Network error: ${err instanceof Error ? err.message : "unknown"}`);
    } finally {
      setLoading(false);
    }
  }

  // ----- Render -----
  return (
    <main className="container">
      <h1>🔐 Envelope Encryption</h1>
      <p className="subtitle">AES-256-GCM · Two-layer envelope encryption demo</p>

      {/* Encrypt Section */}
      <section className="card">
        <h2>📤 Encrypt &amp; Save</h2>

        <div className="form-group">
          <label htmlFor="partyId">Party ID</label>
          <input
            id="partyId"
            type="text"
            placeholder="e.g. merchant-42"
            value={partyId}
            onChange={(e) => setPartyId(e.target.value)}
          />
        </div>

        <div className="form-group">
          <label htmlFor="payload">JSON Payload</label>
          <textarea
            id="payload"
            value={payloadText}
            onChange={(e) => setPayloadText(e.target.value)}
            spellCheck={false}
          />
        </div>

        <button
          className="btn-primary"
          onClick={handleEncrypt}
          disabled={loading}
        >
          {loading ? "⏳" : "🔒"} Encrypt &amp; Save
        </button>
      </section>

      {/* Fetch / Decrypt Section */}
      <section className="card">
        <h2>🔍 Fetch &amp; Decrypt</h2>

        <div className="id-row">
          <div className="form-group">
            <label htmlFor="recordId">Record ID</label>
            <input
              id="recordId"
              type="text"
              placeholder="UUID from encrypt response"
              value={recordId}
              onChange={(e) => setRecordId(e.target.value)}
            />
          </div>
        </div>

        <div className="btn-row" style={{ marginTop: "1rem" }}>
          <button
            className="btn-secondary"
            onClick={handleFetch}
            disabled={loading}
          >
            📥 Fetch
          </button>
          <button
            className="btn-success"
            onClick={handleDecrypt}
            disabled={loading}
          >
            🔓 Decrypt
          </button>
        </div>
      </section>

      {/* Status */}
      {status && (
        <div className={`status ${status.type}`}>{status.msg}</div>
      )}

      {/* Encrypted Record Output */}
      {encryptedRecord && (
        <section className="card">
          <h2>📋 Encrypted Record</h2>
          <div className="output">
            <pre>{JSON.stringify(encryptedRecord, null, 2)}</pre>
          </div>
        </section>
      )}

      {/* Decrypted Result Output */}
      {decryptedResult && (
        <section className="card">
          <h2>✅ Decrypted Result</h2>
          <div className="output">
            <pre>{JSON.stringify(decryptedResult, null, 2)}</pre>
          </div>
        </section>
      )}
    </main>
  );
}
