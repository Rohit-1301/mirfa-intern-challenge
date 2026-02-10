# Mirfa Software Engineer Intern Challenge
## Secure Transactions Mini-App (Turbo + Fastify + Vercel)

Welcome 👋

This challenge simulates a **real engineering task**, not a coding test.

You will build a small production-style app using:

- TurboRepo
- Fastify (API)
- Next.js (Web)
- AES-256-GCM encryption
- Vercel deployment

We evaluate:

- code quality
- system design
- correctness
- debugging ability
- deployment skills
- your ability to explain your work

---

## ⏱ Timebox

Expected effort: **6–10 hours total**  
Deadline: **submit within 2–3 days**

You may use Google / StackOverflow / LLMs, but you **must** understand and explain your solution.

---

## ✅ What to build

Create a Turbo monorepo with:

- `apps/web` → Next.js UI
- `apps/api` → Fastify API
- `packages/crypto` → shared encryption module

The app should allow a user to:

1. Enter a JSON payload + `partyId`
2. Encrypt & store it
3. Retrieve the encrypted record
4. Decrypt it back to original

---

## 🧩 API requirements (Fastify)

### `POST /tx/encrypt`

**Input**
```json
{
  "partyId": "party_123",
  "payload": { "amount": 100 }
}
