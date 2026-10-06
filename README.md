# TrustLayer

A deterministic, framework-aware static application security testing (SAST) scanner tailored for Node.js and Express APIs. TrustLayer identifies critical security risks introduced during rapid development cycles ("Shipped Fast, Left Open"), including client-side payment tampering, unauthenticated endpoints, injection vulnerabilities, and hardcoded secrets.

> **Project Status:** Currently in **Phase 1** (Core Type & Contract Definitions). The repository currently contains the foundational type contracts (`src/types/rule.js`). The core scanning engine, rule implementations, reporters, and demo routes documented below represent the target planned architecture being built across scheduled phases.

---

## Overview

Modern web applications and microservices built with Node.js and Express often prioritize speed to market over secure defaults. Common oversights include trusting client-supplied parameters in payment gateways, omitting authentication middleware on sensitive routes, and concatenating untrusted inputs into database queries.

Generic static analysis tools frequently generate high volumes of false positives or lack context on web framework semantics and transactional APIs. TrustLayer solves this by performing AST-level (Abstract Syntax Tree) intra-handler data-flow and structure analysis specifically tuned for Express patterns.

### Key Characteristics (Design & Architecture)

- **Framework-Aware Static Analysis:** Analyzes Express route handlers, middleware pipelines, and request input sources (`req.body`, `req.params`, `req.query`).
- **Specialized E-Commerce & Payment Checks:** Detects vulnerabilities absent in generic scanners, such as client-controlled payment amounts, missing webhook signature verifications, and client-gated transaction status.
- **Deterministic Core:** Operates completely offline without requiring language model APIs or external network calls.
- **Pure JavaScript Tooling:** Built using pure JavaScript parsing utilities (`@babel/parser`, `@babel/traverse`) without native C-binding dependencies or external CLI wrappers.
- **Modular Auto-Discovery:** Rules placed in `src/rules/` are designed to be discovered and registered dynamically at runtime via ES Modules.
- **Additive AI Enhancement (Planned / Optional):** Optional LLM integration designed to provide contextual exploitation scenarios, attack-chain correlation, and remediation diffs without being a dependency for detection.

---

## Planned Architecture

TrustLayer processes codebases through a structured pipeline:

```
CLI Execution (Commander.js)
  |
  v
File Discovery (Glob: source files & config/secrets)
  |
  +---> JavaScript/Module AST Pipeline (.js, .jsx, .mjs, .cjs) -> Babel AST Parser
  +---> Configuration / Secrets Pipeline (.json, .env) -> Text/Entropy & Key-Value Scanner
  |
  v
Rule Discovery & Execution (Dynamic ESM import from src/rules/*.js)
  |
  v
Findings Collection & Correlation
  |
  +---> [Optional / Planned] AI Contextual Enhancement (Exploit scenarios & diffs)
  |
  v
Report Generation (Terminal, Markdown, or JSON)
```

> **Note on File Discovery & AST Processing:** Only JavaScript/JSX source files (`.js`, `.jsx`, `.mjs`, `.cjs`) undergo `@babel/parser` AST parsing. Environment files (`.env`) and structured data (`.json`) are processed through configuration and text/entropy pattern scanning, not the JavaScript AST parser.

---

## Detection Capabilities (Target Scope)

TrustLayer provides coverage across four key categories:

### 1. Payment Security & Business Logic (Primary Differentiator)
- **Client-Controlled Payment Amount:** Flags instances where client-provided values (`req.body.amount`) flow into payment APIs (`stripe.charges.create`, `stripe.paymentIntents.create`, `razorpay.orders.create`) without server-side database price lookups.
- **Missing Webhook Verification:** Identifies payment webhook handlers that process events without validating signatures via `stripe.webhooks.constructEvent()` or cryptographic timing-safe checks.
- **Client-Side Payment Status Gating:** Detects fulfillment logic guarded by client-submitted payment status flags rather than server-verified webhooks.

### 2. Authentication & Authorization
- **Missing Route Authentication Middleware:** Identifies state-changing or data-retrieval routes that lack authentication middleware guards before the final handler.
- **Insecure Direct Object References (IDOR):** Detects route parameters (`req.params.id`) passed to database operations without user session or ownership verification.

### 3. Injection Flaws
- **SQL Injection:** Detects unparameterized SQL queries built via string concatenation or template literals containing user inputs (`db.query(...)`, `db.run(...)`).
- **Unsafe Code Execution:** Flags dangerous execution sinks (`eval()`, `Function()`, `child_process.exec()`) receiving non-literal values.

### 4. Secrets & Cryptography
- **Hardcoded Secrets:** Scans source files and configuration declarations for hardcoded API keys, JWT secrets, database connection strings, and private keys using pattern heuristics and Shannon entropy analysis.
- **Weak Cryptography:** Flags obsolete hashing algorithms (MD5, SHA-1) in security-sensitive contexts.

---

## Current Development Phase (Phase 1)

The repository is currently in **Phase 1: Shared Type Definitions & Contracts**.

### Current Repository State:
- `src/types/rule.js`: Implemented core JSDoc types (`Rule`, `AnalysisContext`, `Finding`).
- `package.json`, `jsconfig.json`, `vitest.config.js`: Environment and tooling configurations.
- Subsystems across `src/engine/`, `src/rules/`, `src/reporters/`, `src/ai/`, `demo/`, and `tests/` are currently empty scaffolding files awaiting subsequent implementation phases.

---

## Repository Structure

### Current Repository Layout
```
TrustLayer/
├── src/
│   ├── types/
│   │   ├── rule.js             # [Phase 1] JSDoc contracts (Rule, AnalysisContext, Finding)
│   │   ├── finding.js          # Scaffolded type module
│   │   └── report.js           # Scaffolded type module
│   ├── engine/                 # Engine module stubs
│   ├── rules/                  # Security rule module stubs
│   ├── reporters/              # Reporter module stubs
│   ├── ai/                     # AI enhancer stub
│   ├── utils/                  # Utility stubs
│   └── cli.js                  # CLI entrypoint stub
├── demo/                       # Demo reference application (in development)
│   ├── package.json
│   ├── server.js
│   ├── routes/
│   ├── middleware/
│   └── db/
├── demo-fixed/                 # Hardened reference app (planned)
├── tests/                      # Vitest test suite stubs
│   ├── rules/
│   ├── engine/
│   └── fixtures/
├── docs/                       # Project documentation
├── Artifacts/                  # Architecture & design specifications
├── package.json
├── jsconfig.json
├── vitest.config.js
├── AGENTS.md                   # Collaboration rules for AI assistants
├── CONTRIBUTING.md             # Contributor workflow and ownership guidelines
└── README.md
```

### Planned Target Architecture
```
TrustLayer/
├── src/
│   ├── cli.js                  # CLI entry point (Commander.js)
│   ├── types/
│   │   ├── rule.js             # JSDoc type definitions (Rule, Context, Finding)
│   │   ├── finding.js          # Finding type contracts and enums
│   │   └── report.js           # Report data contracts
│   ├── engine/
│   │   ├── scanner.js          # Core scanning orchestrator
│   │   ├── file-discovery.js   # File discovery and exclusion logic
│   │   ├── ast-parser.js       # Centralized Babel AST parser
│   │   └── rule-registry.js    # Dynamic rule auto-discovery via native ESM import()
│   ├── rules/                  # Modular, auto-discovered security rules
│   │   ├── hardcoded-secrets.js
│   │   ├── weak-crypto.js
│   │   ├── sql-injection.js
│   │   ├── missing-input-validation.js
│   │   ├── payment-amount-tampering.js
│   │   ├── missing-webhook-verification.js
│   │   └── missing-auth-middleware.js
│   ├── reporters/
│   │   ├── markdown-reporter.js
│   │   └── json-reporter.js
│   ├── ai/
│   │   └── enhancer.js         # Optional/additive AI analysis and remediation
│   └── utils/
│       ├── ast-helpers.js      # AST node matching and inspection helpers
│       └── patterns.js         # Secret regex definitions and entropy helpers
├── demo/                       # Intentionally vulnerable Express reference app
│   ├── server.js
│   ├── routes/
│   ├── middleware/
│   ├── db/
│   └── package.json
├── demo-fixed/                 # Hardened reference app for before/after validation
├── tests/
│   ├── rules/                  # Unit tests per rule
│   ├── engine/                 # Scanner engine integration tests
│   └── fixtures/               # Vulnerable and secure code samples
├── package.json
├── jsconfig.json
├── vitest.config.js
├── AGENTS.md
├── CONTRIBUTING.md
└── README.md
```

---

## Prerequisites

- Node.js 20.0.0 or higher
- npm 9.0.0 or higher

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/vikalp1817243/TrustLayer.git
   cd TrustLayer
   ```

2. Install scanner dependencies:
   ```bash
   npm install
   ```

3. (Optional) Install demo application dependencies:
   ```bash
   cd demo
   npm install
   cd ..
   ```

---

## Usage (Planned CLI Interface)

> **Note:** The CLI commands below describe the planned interface currently being implemented across feature branches.

```text
████████╗██████╗ ██╗   ██╗███████╗████████╗██╗      █████╗ ██╗   ██╗███████╗██████╗ 
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
   ██║   ██████╔╝██║   ██║███████╗   ██║   ██║     ███████║ ╚████╔╝ █████╗  ██████╔╝
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗
   ██║   ██║  ██║╚██████╔╝███████║   ██║   ███████╗██║  ██║   ██║   ███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

### Basic Scan
Scan current directory (automatically outputs console summary and saves `SECURITY-REPORT.md`):
```bash
node src/cli.js
# or
node src/cli.js scan
```

Scan a specific project or directory:
```bash
node src/cli.js scan ./demo
```

Scan a single file:
```bash
node src/cli.js scan ./routes/checkout.js
```

### Output Formats & Smart Saving
TrustLayer automatically infers file extensions and generates formatted reports:
```bash
# Markdown report (auto-appends .md if omitted)
node src/cli.js scan ./demo -o audit

# JSON report (auto-appends .json and switches format)
node src/cli.js scan ./demo -o audit -f json

# Console output only (suppresses file creation)
node src/cli.js scan ./demo --no-report
```

### Scanning the Demo Application
Run a scan against the included vulnerable reference application:
```bash
npm run scan:demo
```

---

## Rule Implementation Contract

Every rule in `src/rules/` exports a default object following this structure defined in `src/types/rule.js`:

```javascript
/**
 * @typedef {import('../types/rule.js').Rule} Rule
 */

/** @type {Rule} */
const rule = {
  id: 'category/kebab-case-name',
  name: 'Descriptive Title',
  severity: 'critical', // 'critical' | 'high' | 'medium' | 'low'
  category: 'payment',  // 'secrets' | 'injection' | 'payment' | 'auth'
  description: 'Short summary of the vulnerability pattern.',
  defaultExplanation: 'In-depth description of the vulnerability and attack vector.',
  defaultRemediation: 'Guidance and secure code snippet showing how to resolve the issue.',
  analyze(context) {
    const findings = [];
    const { filePath, fileContent, ast, lines } = context;

    if (!ast) return findings;

    // Perform traversal using @babel/traverse on the provided AST
    // Append findings matching the Finding specification

    return findings;
  }
};

export default rule;
```

---

## Testing

Tests are written using Vitest. Every rule must maintain at least three test scenarios:
1. True Positive: Detects vulnerable patterns accurately.
2. True Negative: Ignores safe and remediated code without false alarms.
3. Edge Case: Handles empty handlers, missing parameters, and alternative signatures safely.

Execute the test suite:
```bash
# Run all tests once
npm test

# Run tests in watch mode
npm run test:watch
```

---

## License

This project is licensed under the ISC License.