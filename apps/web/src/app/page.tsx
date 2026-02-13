"use client";

import { useState, useEffect, useCallback } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

interface TxSummary {
  id: string;
  partyId: string;
  createdAt: string;
  alg: string;
}

export default function Home() {
  // ----- Form state -----
  const [partyId, setPartyId] = useState("");
  const [payloadText, setPayloadText] = useState(
    '{\n  "amount": 100,\n  "currency": "AED"\n}'
  );
  const [lookupId, setLookupId] = useState("");

  // ----- Data state -----
  const [transactions, setTransactions] = useState<TxSummary[]>([]);
  const [encryptedRecord, setEncryptedRecord] = useState<object | null>(null);
  const [decryptedResult, setDecryptedResult] = useState<object | null>(null);
  const [selectedTxId, setSelectedTxId] = useState<string | null>(null);

  // ----- UI state -----
  const [status, setStatus] = useState<{
    type: "error" | "success";
    msg: string;
  } | null>(null);
  const [loading, setLoading] = useState(false);

  // ----- Fetch transaction list -----
  const fetchTransactions = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/tx`);
      if (res.ok) {
        const data = await res.json();
        setTransactions(data);
      }
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    fetchTransactions();
  }, [fetchTransactions]);

  // ----- Helpers -----
  function showError(msg: string) {
    setStatus({ type: "error", msg });
  }
  function showSuccess(msg: string) {
    setStatus({ type: "success", msg });
  }
  function clearResults() {
    setEncryptedRecord(null);
    setDecryptedResult(null);
    setSelectedTxId(null);
    setStatus(null);
  }

  // ----- Encrypt & Save -----
  async function handleEncrypt() {
    clearResults();

    if (!partyId.trim()) return showError("Party ID is required");

    let payload: object;
    try {
      payload = JSON.parse(payloadText);
      if (typeof payload !== "object" || Array.isArray(payload) || payload === null)
        throw new Error();
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

      if (!res.ok) return showError(data.error || "Encryption failed");

      setEncryptedRecord(data);
      setSelectedTxId(data.id);
      setLookupId(data.id);
      showSuccess(`Encrypted & saved — ID: ${data.id}`);
      fetchTransactions();
    } catch (err) {
      showError(`Network error: ${err instanceof Error ? err.message : "unknown"}`);
    } finally {
      setLoading(false);
    }
  }

  // ----- Fetch Record -----
  async function handleFetch(id?: string) {
    const txId = (id || lookupId).trim();
    setStatus(null);
    setDecryptedResult(null);

    if (!txId) return showError("Transaction ID is required");

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/tx/${txId}`);
      const data = await res.json();

      if (!res.ok) return showError(data.error || "Fetch failed");

      setEncryptedRecord(data);
      setSelectedTxId(txId);
      setLookupId(txId);
      showSuccess("Encrypted record fetched");
    } catch (err) {
      showError(`Network error: ${err instanceof Error ? err.message : "unknown"}`);
    } finally {
      setLoading(false);
    }
  }

  // ----- Decrypt -----
  async function handleDecrypt() {
    const txId = (selectedTxId || lookupId).trim();
    setStatus(null);

    if (!txId) return showError("Transaction ID is required");

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/tx/${txId}/decrypt`, { method: "POST" });
      const data = await res.json();

      if (!res.ok) return showError(data.error || "Decryption failed");

      setDecryptedResult(data);
      showSuccess("Decrypted successfully");
    } catch (err) {
      showError(`Network error: ${err instanceof Error ? err.message : "unknown"}`);
    } finally {
      setLoading(false);
    }
  }

  // ----- Click a transaction in the list -----
  function handleSelectTx(id: string) {
    setLookupId(id);
    handleFetch(id);
  }

  // ----- Render -----
  return (
    <main className="page">
      {/* ===== Header ===== */}
      <header className="header">
        <h1>Secure Transactions</h1>
        <p className="subtitle">
          End-to-end encrypted transaction storage using AES-256-GCM envelope
          encryption
        </p>
        <div className="badge">🔒 AES-256-GCM Encryption Active</div>
      </header>

      {/* ===== Top Row: Create + Lookup ===== */}
      <div className="grid-2">
        {/* Left — Create Transaction */}
        <section className="card">
          <h2>
            <span className="icon icon-lock">🔒</span> Create Transaction
          </h2>

          <div className="form-group">
            <label htmlFor="partyId">Party ID</label>
            <input
              id="partyId"
              type="text"
              placeholder="e.g. party_123"
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
            className="btn btn-primary full-width"
            onClick={handleEncrypt}
            disabled={loading}
          >
            {loading ? "⏳" : "🔒"} Encrypt & Save
          </button>
        </section>

        {/* Right — Lookup */}
        <section className="card">
          <h2>
            <span className="icon icon-lookup">🟢</span> Lookup
          </h2>

          <div className="form-group">
            <label htmlFor="lookupId">Transaction ID</label>
            <input
              id="lookupId"
              type="text"
              placeholder="Enter transaction UUID"
              value={lookupId}
              onChange={(e) => setLookupId(e.target.value)}
            />
          </div>

          <div className="btn-stack">
            <button
              className="btn btn-fetch"
              onClick={() => handleFetch()}
              disabled={loading}
            >
              📦 Fetch Record
            </button>
            <button
              className="btn btn-decrypt"
              onClick={handleDecrypt}
              disabled={loading}
            >
              🔓 Decrypt
            </button>
          </div>
        </section>
      </div>

      {/* ===== Status ===== */}
      {status && (
        <div className={`status ${status.type}`}>{status.msg}</div>
      )}

      {/* ===== Results Row ===== */}
      {(encryptedRecord || decryptedResult) && (
        <div className="grid-2">
          {encryptedRecord && (
            <section className="card">
              <h2>📋 Encrypted Record</h2>
              <div className="output">
                <pre>{JSON.stringify(encryptedRecord, null, 2)}</pre>
              </div>
            </section>
          )}
          {decryptedResult && (
            <section className="card">
              <h2>✅ Decrypted Result</h2>
              <div className="output output-success">
                <pre>{JSON.stringify(decryptedResult, null, 2)}</pre>
              </div>
            </section>
          )}
        </div>
      )}

      {/* ===== Recent Transactions ===== */}
      <section className="card">
        <h2>📜 Recent Transactions</h2>
        {transactions.length === 0 ? (
          <p className="empty-text">
            No transactions yet. Create one above to get started.
          </p>
        ) : (
          <div className="tx-list">
            {transactions.map((tx) => (
              <button
                key={tx.id}
                className={`tx-item ${selectedTxId === tx.id ? "active" : ""}`}
                onClick={() => handleSelectTx(tx.id)}
              >
                <div className="tx-item-top">
                  <span className="tx-id">{tx.id}</span>
                  <span className="tx-alg">{tx.alg}</span>
                </div>
                <div className="tx-item-bottom">
                  <span className="tx-party">Party: {tx.partyId}</span>
                  <span className="tx-time">
                    {new Date(tx.createdAt).toLocaleString()}
                  </span>
                </div>
              </button>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
