# TrustLayer (SecAuditScanner)

A deterministic, framework-aware static application security testing (SAST) scanner tailored for Node.js and Express APIs. TrustLayer identifies critical security risks introduced during rapid development cycles ("Shipped Fast, Left Open"), including client-side payment tampering, unauthenticated endpoints, injection vulnerabilities, and hardcoded secrets.

---

## Overview

Modern web applications and microservices built with Node.js and Express often prioritize speed to market over secure defaults. Common oversights include trusting client-supplied parameters in payment gateways, omitting authentication middleware on sensitive routes, and concatenating untrusted inputs into database queries.

Generic static analysis tools frequently generate high volumes of false positives or lack context on web framework semantics and transactional APIs. TrustLayer solves this by performing AST-level (Abstract Syntax Tree) intra-handler data-flow and structure analysis specifically tuned for Express patterns.

### Key Characteristics

- Framework-Aware Static Analysis: Analyzes Express route handlers, middleware pipelines, and request input sources (`req.body`, `req.params`, `req.query`).
- Specialized E-Commerce & Payment Checks: Detects vulnerabilities absent in generic scanners, such as client-controlled payment amounts, missing webhook signature verifications, and client-gated transaction status.
- Deterministic Core: Operates completely offline without requiring language model APIs or external network calls.
- Pure JavaScript Tooling: Built using pure JavaScript parsing utilities (`@babel/parser`, `@babel/traverse`) without native C-binding dependencies or external CLI wrappers.
- Modular Auto-Discovery: Rules placed in `src/rules/` are discovered and registered dynamically at runtime via ES Modules.
- Additive AI Enhancement: Optional LLM integration provides contextual exploitation scenarios, attack-chain correlation, and remediation diffs without being a dependency for detection.

---

## Architecture

TrustLayer processes codebases through a structured pipeline:

```
CLI Execution (Commander.js)
  |
  v
File Discovery (Glob: .js, .jsx, .mjs, .cjs, .json, .env)
  |
  v
AST Parsing (@babel/parser with JSX support)
  |
  v
Rule Discovery & Execution (Dynamic ESM import from src/rules/*.js)
  |
  v
Findings Collection & Correlation
  |
  +---> [Optional] AI Contextual Enhancement (Exploit scenarios & diffs)
  |
  v
Report Generation (Terminal, Markdown, or JSON)
```

---

## Detection Capabilities

TrustLayer provides coverage across four key categories:

### 1. Payment Security & Business Logic (Primary Differentiator)
- Client-Controlled Payment Amount: Flags instances where client-provided values (`req.body.amount`) flow into payment APIs (`stripe.charges.create`, `stripe.paymentIntents.create`, `razorpay.orders.create`) without server-side database price lookups.
- Missing Webhook Verification: Identifies payment webhook handlers that process events without validating signatures via `stripe.webhooks.constructEvent()` or cryptographic timing-safe checks.
- Client-Side Payment Status Gating: Detects fulfillment logic guarded by client-submitted payment status flags rather than server-verified webhooks.

### 2. Authentication & Authorization
- Missing Route Authentication Middleware: Identifies state-changing or data-retrieval routes that lack authentication middleware guards before the final handler.
- Insecure Direct Object References (IDOR): Detects route parameters (`req.params.id`) passed to database operations without user session or ownership verification.

### 3. Injection Flaws
- SQL Injection: Detects unparameterized SQL queries built via string concatenation or template literals containing user inputs (`db.query(...)`, `db.run(...)`).
- Unsafe Code Execution: Flags dangerous execution sinks (`eval()`, `Function()`, `child_process.exec()`) receiving non-literal values.

### 4. Secrets & Cryptography
- Hardcoded Secrets: Scans source files and configuration declarations for hardcoded API keys, JWT secrets, database connection strings, and private keys using pattern heuristics and Shannon entropy analysis.
- Weak Cryptography: Flags obsolete hashing algorithms (MD5, SHA-1) in security-sensitive contexts.

---

## Repository Structure

```
SecAuditScanner/
├── src/
│   ├── cli.js                  # CLI entry point
│   ├── types/
│   │   └── rule.js             # JSDoc type definitions (Rule, Context, Finding)
│   ├── engine/
│   │   ├── scanner.js          # Core scanning orchestrator
│   │   ├── file-discovery.js   # File discovery and exclusion logic
│   │   ├── ast-parser.js       # Centralized Babel AST parser
│   │   └── rule-registry.js    # Dynamic rule auto-discovery
│   ├── rules/                  # Isolated rule modules
│   │   ├── hardcoded-secrets.js
│   │   ├── weak-crypto.js
│   │   ├── sql-injection.js
│   │   ├── missing-input-validation.js
│   │   ├── payment-amount-tampering.js
│   │   ├── missing-webhook-verification.js
│   └── └── missing-auth-middleware.js
│   ├── reporters/
│   │   ├── markdown-reporter.js
│   │   └── json-reporter.js
│   ├── ai/
│   │   └── enhancer.js         # Optional AI analysis and remediation
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
├── AGENTS.md                   # Collaboration rules for AI assistants
├── ROLES.md                    # Team member roles & AI boundary selector
├── CONTRIBUTING.md             # Contributor workflow and ownership guidelines
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
   git clone https://github.com/<your-username>/SecAuditScanner.git
   cd SecAuditScanner
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

---

## Current Development Status

| Component | Status | Owner | Highlights |
|---|---|---|---|
| **Core Types & Contracts** | ✅ Complete | Team Lead | JSDoc contracts for `Rule`, `Finding`, `AnalysisContext`, `ScanReport` |
| **Engine & Pipeline** | ✅ Complete | Team Lead | Babel AST parser, dynamic ESM rule discovery, file discovery, orchestrator |
| **AST Helpers & Patterns** | ✅ Complete | Team Lead | `isMethodCall`, `isExpressRoute`, `isReqAccess`, Shannon entropy, unit tests |
| **CLI & Terminal UX** | ✅ Complete | Team Lead | ANSI Shadow banner, live Ora spinner, smart default report writing (`SECURITY-REPORT.md`) |
| **Secrets & Crypto Rules** | 🔄 In Progress | Member 2 | Hardcoded secret detection, weak hashing, high-entropy token analysis |
| **Injection Rules** | 🔄 In Progress | Member 3 | SQL injection, template literal taint tracking, input validation |
| **Payment & Auth Rules** | 🔄 In Progress | Member 4 | Client-controlled amount, webhook signature verification, missing auth |
| **Reporters & AI** | 🔄 In Progress | Member 5 | Markdown and JSON generators, LLM exploit scenarios, demo routes |

> 👥 **Working on the project?** See [ROLES.md](./ROLES.md) to identify your role and file ownership boundaries before editing files.

---

## Usage

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

Every rule in `src/rules/` exports a default object following this structure:

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