# 👥 ROLES.md — Team Member Roles & AI Agent Boundary Guide

> **MANDATORY NOTICE FOR ALL AI AGENTS & DEVELOPERS:**
> To prevent git merge conflicts and maintain strict modular separation, this project uses an isolated role-based ownership model.
> **Before generating code or editing files, every human developer or AI assistant MUST declare their active role and adhere strictly to the allowed boundaries below.**

---

## 🧭 How to Select Your Role in AI Prompts

When starting a conversation or task with an AI assistant (Antigravity, Cursor, Claude Code, Copilot, Gemini CLI, Aider, etc.), begin your prompt with:

```markdown
I am working as [Member X: Role Name].
Please adhere strictly to the file ownership rules and branch directives in ROLES.md.
```

---

## 📊 Team Member Role Matrix

| Member | Role | Assigned Branch | Owned Files (Can Create / Edit) | Status |
|---|---|---|---|---|
| **Member 1** | **Team Lead & Core Integrator** | `main` / `feature/core-engine` / `feature/ast-utils` / `feature/cli` | `src/engine/*`, `src/cli.js`, `src/types/*`, `src/utils/*`, `tests/engine/*`, `tests/utils/*`, `demo/server.js`, `demo/db/*`, configs | 🟢 Completed (Core Pipeline, CLI, Demo Skeleton & Tests) |
| **Member 2** | **Secrets & Cryptography Specialist** | `feature/secrets-crypto` | `src/rules/hardcoded-secrets.js`, `src/rules/weak-crypto.js`, `tests/rules/hardcoded-secrets.test.js`, `tests/rules/weak-crypto.test.js` | 🟡 In Progress |
| **Member 3** | **Injection & Input Flaws Specialist** | `feature/injection-rules` | `src/rules/sql-injection.js`, `src/rules/missing-input-validation.js`, `tests/rules/sql-injection.test.js`, `tests/rules/missing-input-validation.test.js` | 🟡 In Progress |
| **Member 4** | **Payment & Authentication Specialist** | `feature/auth-payment-rules` | `src/rules/payment-amount-tampering.js`, `src/rules/missing-webhook-verification.js`, `src/rules/missing-auth-middleware.js`, `tests/rules/payment-*.test.js`, `tests/rules/auth-*.test.js` | 🟡 In Progress |
| **Member 5** | **Reporting, Demo & AI Specialist** | `feature/demo-reporting` | `src/reporters/*`, `src/ai/*`, `demo/routes/*`, `demo/middleware/*`, `demo-fixed/*`, `tests/reporters/*` | 🟡 In Progress |

---

## 🛡️ Detailed Role Specifications

### 👑 Member 1: Team Lead & Core Integrator
- **Branch**: `main`, `feature/core-engine`, `feature/ast-utils`, `feature/cli`
- **Ownership**:
  - `src/types/` — Data contracts (`rule.js`, `finding.js`, `report.js`)
  - `src/engine/` — Pipeline orchestrator (`scanner.js`, `ast-parser.js`, `file-discovery.js`, `rule-registry.js`)
  - `src/utils/` — Shared patterns & AST helpers (`ast-helpers.js`, `patterns.js`)
  - `src/cli.js` — CLI entrypoint, Commander.js flags, ANSI Shadow banner
  - `demo/server.js`, `demo/db/` — Demo server skeleton and database mock
- **Key Directives**:
  - Review PRs from Members 2–5.
  - Maintain the `Rule` and `Finding` contracts.
  - Keep test suite passing and handle core integration.

---

### 🔑 Member 2: Secrets & Cryptography Specialist
- **Branch**: `feature/secrets-crypto`
- **Ownership**:
  - `src/rules/hardcoded-secrets.js`
  - `src/rules/weak-crypto.js`
  - `tests/rules/hardcoded-secrets.test.js`
  - `tests/rules/weak-crypto.test.js`
- **Responsibilities**:
  - Detect API keys, JWT secrets, database credentials using regex and Shannon entropy (`src/utils/ast-helpers.js`).
  - Detect obsolete hashing algorithms (`md5`, `sha1`) and insecure random number generators for security tokens.
  - Avoid literal live keys in tests (use string concatenation like `['sk', 'live', '...'].join('_')` to avoid GitHub Push Protection).

---

### 💉 Member 3: Injection & Input Flaws Specialist
- **Branch**: `feature/injection-rules`
- **Ownership**:
  - `src/rules/sql-injection.js`
  - `src/rules/missing-input-validation.js`
  - `tests/rules/sql-injection.test.js`
  - `tests/rules/missing-input-validation.test.js`
- **Responsibilities**:
  - Detect unparameterized SQL queries (`db.query`, `db.run`, `pool.query`) built via string concatenation or template literals containing user inputs (`req.body`, `req.query`, `req.params`).
  - Flag untrusted inputs flowing directly into sensitive execution or database sinks.
  - Leverage `isMethodCall` and `isReqAccess` from `src/utils/ast-helpers.js`.

---

### 💳 Member 4: Payment & Authentication Specialist (Hackathon Differentiator)
- **Branch**: `feature/auth-payment-rules`
- **Ownership**:
  - `src/rules/payment-amount-tampering.js`
  - `src/rules/missing-webhook-verification.js`
  - `src/rules/missing-auth-middleware.js`
  - `tests/rules/payment-amount-tampering.test.js`
  - `tests/rules/missing-webhook-verification.test.js`
  - `tests/rules/missing-auth-middleware.test.js`
- **Responsibilities**:
  - **Payment Amount Tampering**: Client-controlled `req.body.amount` flowing into `stripe.charges.create`, `stripe.paymentIntents.create`, or `razorpay.orders.create`.
  - **Missing Webhook Verification**: Webhook route handlers missing signature verification (`stripe.webhooks.constructEvent` or `crypto.timingSafeEqual`).
  - **Missing Auth Middleware**: Sensitive routes lacking authentication guards in the Express route chain.

---

### 📊 Member 5: Reporting, Demo & AI Specialist
- **Branch**: `feature/demo-reporting`
- **Ownership**:
  - `src/reporters/markdown-reporter.js`
  - `src/reporters/json-reporter.js`
  - `src/ai/enhancer.js`
  - `demo/routes/*` (vulnerable reference routes: `auth.js`, `products.js`, `orders.js`, `checkout.js`, `webhook.js`)
  - `demo-fixed/*` (hardened reference routes demonstrating remediations)
  - `tests/reporters/*`
- **Responsibilities**:
  - Generate clean Markdown (`SECURITY-REPORT.md`) and JSON reports.
  - Implement additive AI enhancement (LLM-generated exploitation scenarios, attack-chain correlation, and fix diffs).
  - Prepare the before/after demo routes showing 8 initial findings reducing to 0 after fixes.

---

## ⛔ Forbidden AI Agent Actions Across All Roles

1. ❌ **NEVER edit files outside your assigned role's boundary.**
2. ❌ **NEVER modify `src/types/rule.js` or `src/types/finding.js`** without explicit Team Lead confirmation.
3. ❌ **NEVER add new npm dependencies** without prior human confirmation.
4. ❌ **NEVER push directly to `main`** — all contributions must go through feature branches and pull requests.
5. ❌ **NEVER introduce cross-file taint analysis** — keep all rule analysis intra-file and intra-handler.
