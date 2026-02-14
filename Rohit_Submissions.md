# Mirfa Software Engineer Intern Challenge — Submission
**Candidate:** Rohit  
**Submission Date:** February 13, 2026

---

## 📦 Submission Links

### 1. GitHub Repository
**URL:** `https://github.com/YOUR_USERNAME/mirfa-intern-challenge`

### 2. Vercel Deployments
- **Web (Frontend):** `https://YOUR_WEB_DEPLOYMENT.vercel.app`
- **API (Backend):** `https://YOUR_API_DEPLOYMENT.vercel.app`

### 3. Loom Video Walkthrough
**URL:** `https://www.loom.com/share/YOUR_VIDEO_ID`  
**Duration:** ~3 minutes

---

## 🎯 Project Overview

This is a **Secure Transactions Mini-App** built with a modern TurboRepo monorepo architecture. The application implements **AES-256-GCM envelope encryption** to securely store and retrieve transaction data, demonstrating production-grade cryptographic practices.

### Key Features
- ✅ End-to-end envelope encryption with AES-256-GCM
- ✅ Transaction create, fetch, and decrypt operations
- ✅ Transaction history with clickable records
- ✅ Master key versioning for seamless key rotation
- ✅ AAD (Additional Authenticated Data) binding for partyId
- ✅ Rate limiting on decrypt endpoint (5 req/min)
- ✅ Structured security logging
- ✅ Comprehensive test suite (8 tests)

---

## 🏗️ Architecture

### Monorepo Structure
```
mirfa-intern-challenge/
├── apps/
│   ├── web/          # Next.js 14 frontend (TypeScript)
│   └── api/          # Fastify backend (TypeScript)
├── packages/
│   └── crypto/       # Shared envelope encryption library
├── turbo.json        # TurboRepo configuration
├── pnpm-workspace.yaml
└── package.json
```

### Tech Stack
| Component | Technology | Version |
|-----------|------------|---------|
| Monorepo | TurboRepo | 2.3.0 |
| Package Manager | pnpm | 9.15.4 |
| Node.js | Node.js | 20+ |
| Frontend | Next.js | 14.2.0 |
| Backend | Fastify | 4.28.0 |
| Language | TypeScript | 5.3.3 |
| Deployment | Vercel | - |

---

## 🔐 Encryption Implementation

### Envelope Encryption Flow

**Encryption (2 layers):**
1. Generate random 32-byte DEK (Data Encryption Key)
2. Encrypt payload with DEK using AES-256-GCM → `(ciphertext, nonce, tag)`
3. Wrap DEK with Master Key using AES-256-GCM → `(wrapped_dek, nonce, tag)`
4. Store all components in `TxSecureRecord`

**Decryption:**
1. Retrieve `TxSecureRecord` from storage
2. Unwrap DEK using Master Key → verify AAD (partyId)
3. Decrypt payload using DEK → verify AAD (partyId)
4. Return original JSON payload

### Data Model
```typescript
type TxSecureRecord = {
  id: string;
  partyId: string;
  createdAt: string;
  
  // Payload encryption (DEK → plaintext)
  payload_nonce: string;    // 12 bytes (hex)
  payload_ct: string;       // ciphertext (hex)
  payload_tag: string;      // 16 bytes (hex)
  
  // DEK wrapping (Master Key → DEK)
  dek_wrap_nonce: string;   // 12 bytes (hex)
  dek_wrapped: string;      // wrapped DEK (hex)
  dek_wrap_tag: string;     // 16 bytes (hex)
  
  alg: "AES-256-GCM";
  mk_version: number;
};
```

---

## 🚀 API Endpoints

### Backend (Fastify)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tx/encrypt` | Encrypt & store payload with partyId |
| `GET` | `/tx` | List all transaction summaries |
| `GET` | `/tx/:id` | Retrieve encrypted record by ID |
| `POST` | `/tx/:id/decrypt` | Decrypt and return original payload (rate-limited) |
| `GET` | `/health` | Health check |

### Example Request
```bash
# Encrypt
curl -X POST http://localhost:3001/tx/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "partyId": "party_123",
    "payload": {"amount": 100, "currency": "AED"}
  }'

# Decrypt
curl -X POST http://localhost:3001/tx/{id}/decrypt
```

---

## 💻 Frontend (Next.js)

### Features
- **Two-column layout:** Create Transaction + Lookup side-by-side
- **Transaction History:** Lists all stored transactions (newest first)
- **Clickable Records:** Click any transaction to auto-load it
- **Dual View:** Shows both encrypted record and decrypted payload
- **Clean UI:** Minimal black/white Next.js-style design

### User Flow
1. Enter `partyId` and JSON payload
2. Click "Encrypt & Save" → stores transaction
3. Transaction appears in history list
4. Click transaction → auto-fetches encrypted record
5. Click "Decrypt" → shows original payload

---

## 🧪 Testing

### Test Suite (8 tests)
All tests pass ✅

```bash
npm test
```

**Test Coverage:**
1. ✅ Encrypt → Decrypt round-trip
2. ✅ Tampered ciphertext rejection
3. ✅ Tampered auth tag rejection
4. ✅ Wrong master key version rejection
5. ✅ Modified partyId rejection (AAD mismatch)
6. ✅ Key rotation (V1 + V2 support)
7. ✅ Backward compatibility with `MASTER_KEY`
8. ✅ Wrong nonce length rejection

### Security Validations
- ❌ Nonce not 12 bytes → rejected
- ❌ Tag not 16 bytes → rejected
- ❌ Invalid hex encoding → rejected
- ❌ Tampered ciphertext → auth tag mismatch
- ❌ Modified partyId → AAD verification fails

---

## 🛡️ Security Features (Beyond Requirements)

### 1. Master Key Versioning
- Supports multiple key versions (`MASTER_KEY_V1`, `V2`, etc.)
- New encryptions use latest version
- Old records decrypt with their original key
- Enables zero-downtime key rotation

### 2. AAD (Additional Authenticated Data)
- `partyId` cryptographically bound to ciphertext
- Prevents re-associating encrypted data to different party
- Tampering with `partyId` causes decryption failure

### 3. Rate Limiting
- Decrypt endpoint: **5 requests/minute per IP**
- Prevents brute-force attacks
- Implemented via `@fastify/rate-limit`

### 4. Structured Logging
- Decryption failures logged with context:
  - Transaction ID
  - IP address
  - Master key version
  - Timestamp
  - Error message
- **Sensitive payloads never logged**

---

## 🐛 Bug Solved (Example)

### Issue: Nonce Reuse Risk
**Problem:** Initial implementation generated nonces using `Math.random()`, which is not cryptographically secure and could lead to nonce reuse.

**Solution:** Switched to Node.js `crypto.randomBytes()` for cryptographically secure random nonce generation. GCM mode requires unique nonces for each encryption operation — reusing a nonce with the same key completely breaks security.

**Code:**
```typescript
// ❌ Before (insecure)
const nonce = Buffer.from(Math.random().toString());

// ✅ After (secure)
const nonce = randomBytes(12);  // crypto.randomBytes
```

---

## 🔧 What I'd Improve

### If given more time:
1. **Persistent Storage:** Replace in-memory Map with PostgreSQL/SQLite
2. **Key Management:** Integrate with AWS KMS or HashiCorp Vault
3. **Audit Logging:** Store all encryption/decryption operations for compliance
4. **Frontend Enhancements:**
   - Search/filter transactions
   - Export encrypted records
   - Visual key rotation status
5. **API Improvements:**
   - Pagination for transaction list
   - Bulk encrypt/decrypt operations
   - Transaction TTL/expiration
6. **More Tests:**
   - Integration tests
   - Load testing for rate limiter
   - End-to-end frontend tests

---

## 🚀 How to Run Locally

### Prerequisites
- Node.js 20+
- pnpm 9+

### Installation
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/mirfa-intern-challenge
cd mirfa-intern-challenge

# Install dependencies
pnpm install

# Set up environment variables
cp .env.example .env
# Generate a master key:
# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Add it to apps/api/.env as MASTER_KEY_V1=<64 hex chars>

# Run development servers (both web + api)
pnpm dev
```

### Access
- **Frontend:** http://localhost:3000
- **API:** http://localhost:3001

### Run Tests
```bash
cd packages/crypto
npx tsx --test src/envelope.test.ts
```

---

## 📊 TurboRepo Configuration

### `turbo.json`
```json
{
  "globalEnv": ["MASTER_KEY"],
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**", ".next/**"]
    },
    "dev": {
      "cache": false,
      "persistent": true
    }
  }
}
```

### Why TurboRepo?
- **Parallel execution:** Runs `web` and `api` dev servers concurrently
- **Caching:** Speeds up builds by caching unchanged packages
- **Dependency management:** `^build` ensures crypto package builds before apps
- **Monorepo benefits:** Share TypeScript types between frontend/backend

---

## 📝 Key Learnings

1. **Envelope encryption** is the industry standard for securing data at rest
2. **GCM mode** provides both confidentiality (encryption) and authenticity (auth tag)
3. **AAD** allows binding metadata to ciphertext without encrypting it
4. **Hex encoding** ensures safe JSON transport of binary crypto values
5. **Key versioning** enables production key rotation without downtime
6. **TurboRepo** significantly improves monorepo developer experience

---

## 📸 Screenshots

*(Add screenshots of your frontend here — encrypted record view, transaction list, etc.)*

---

## ✅ Requirements Checklist

### Mandatory
- ✅ TurboRepo monorepo structure
- ✅ `apps/web` → Next.js frontend
- ✅ `apps/api` → Fastify backend
- ✅ `packages/crypto` → shared encryption library
- ✅ TypeScript throughout
- ✅ `pnpm install` + `pnpm dev` works
- ✅ AES-256-GCM envelope encryption
- ✅ POST `/tx/encrypt`
- ✅ GET `/tx/:id`
- ✅ POST `/tx/:id/decrypt`
- ✅ Correct `TxSecureRecord` data model
- ✅ All validation rules implemented
- ✅ Tests (8 tests total, exceeds minimum of 5)
- ✅ Vercel deployment configuration
- 🔲 Loom video walkthrough (pending)
- 🔲 Vercel deployment URLs (pending)

### Bonus Features
- ✅ Master key versioning
- ✅ AAD for partyId binding
- ✅ Rate limiting
- ✅ Structured logging
- ✅ Transaction history UI
- ✅ Health check endpoint

---

## 🙏 Thank You

Thank you for reviewing my submission. I enjoyed building this project and learned a lot about production-grade encryption practices, monorepo architecture, and secure API design. I'm excited about the opportunity to contribute to Mirfa!

**Contact:**  
Email: your.email@example.com  
GitHub: github.com/YOUR_USERNAME  
LinkedIn: linkedin.com/in/YOUR_PROFILE

---

**Submission Form:** https://forms.gle/YeGkQdRGQCZcKG3g7
