# 🛡️ TrustLayer

> **Deterministic, Framework-Aware Static Security Scanner for Node.js & Express APIs**  
> *Built for the Cybersecurity Hackathon — Theme: "Shipped Fast, Left Open"*

[![Node.js Version](https://img.shields.io/badge/Node.js-20%2B-brightgreen.svg)](https://nodejs.org/)
[![Test Suite](https://img.shields.io/badge/Vitest-164%20passed-success.svg)](https://vitest.dev/)
[![Language](https://img.shields.io/badge/Language-Modern%20ESM-yellow.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![License](https://img.shields.io/badge/License-ISC-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Design-Zero--LLM%20Detection%20Core-orange.svg)](#core-architecture)

---

## 📌 Executive Summary

When developers build and deploy e-commerce backends at rapid pace, security checks are frequently left behind. Critical oversights—such as accepting payment amounts directly from client requests, failing to verify webhook cryptographic signatures, omitting authentication middleware on internal endpoints, and concatenating input into database queries—are frequently shipped straight to production.

Existing static analysis tools (Semgrep, ESLint-security, Gitleaks, SonarQube) suffer from two major problems:
1. **Zero Domain Awareness for Payments**: Traditional SAST scanners have no rules for Stripe, Razorpay, or payment transaction tampering.
2. **Framework Ignorance**: Generic tools fail to understand Express middleware chains, leading to high false-positive rates or completely missed authorization flaws.

**TrustLayer** solves this with an ultra-fast, deterministic, intra-handler AST analysis engine tailored specifically for Node.js/Express APIs.

---

## ✨ Key Capabilities & Differentiators

- 💳 **Specialized Payment Security (Primary Differentiator)**  
  Detects client-controlled transaction amounts (`req.body.amount` flowing into Stripe/Razorpay APIs), unverified webhook signatures, and client-side payment status gating before code reaches production.
- ⚡ **Deterministic & Instant Core**  
  Zero dependency on external networks or LLM APIs for vulnerability detection. High-speed AST traversal powered directly by `@babel/parser` and `@babel/traverse` in milliseconds.
- 🌐 **Express Framework Awareness**  
  Tracks Express input sources (`req.body`, `req.params`, `req.query`, `req.headers`) and inspects middleware authorization chains across route definitions.
- 🔌 **Dynamic Rule Auto-Discovery**  
  Rules in `src/rules/*.js` are discovered and registered at runtime via native ES module `import()`. No centralized hardcoded rule registry needed.
- 🤖 **Additive AI Enhancement & Attack Chains**  
  Vulnerability detection is 100% deterministic. Additive offline heuristics correlate independent findings into multi-stage attack chains; optional LLM integration (Gemini / OpenAI) crafts real-world exploit walkthroughs and remediation diffs.
- 📊 **Executive & CI/CD Reporting**  
  Generates clean GitHub Flavored Markdown (GFM) executive summaries, structured JSON, and OASIS SARIF v2.1.0 output for direct GitHub Code Scanning integration.
- 🪶 **Pure JavaScript Tooling**  
  Zero native C-bindings or tree-sitter compilation hazards; runs out-of-the-box on Node 20+ anywhere.

---

## 🏗️ Core Architecture & Pipeline

```mermaid
graph TD
    A["CLI Entrypoint (trustlayer scan)"] --> B["File Discovery (Glob: .js, .mjs, .cjs)"]
    B --> C["Babel AST Parser (@babel/parser)"]
    D["Rule Registry (Dynamic ESM Loader)"] --> E["Scanner Engine (Intra-Handler Traversal)"]
    C --> E
    E --> F["Structured Findings (Rule, File, Line, Code)"]
    F --> G["Optional AI Enhancer & Attack Chain Correlator"]
    G --> H["Report Generators"]
    F --> H
    H --> I["Console Summary (ANSI Formatted Table)"]
    H --> J["Markdown Report (SECURITY-REPORT.md)"]
    H --> K["SARIF / JSON Export (audit.sarif / audit.json)"]
```

---

## 🚦 Project Status & Implementation Matrix

All 5 core layers and specialized rule categories are **fully implemented, integrated, and verified** with **133/133 tests passing**:

| Subsystem / Layer | Component / Files | Status | Test Coverage |
|---|---|:---:|:---:|
| **Data Contracts** | `src/types/rule.js`, `src/types/finding.js`, `src/types/report.js` | 🟢 Completed | JSDoc Validated |
| **AST & Pattern Helpers** | `src/utils/ast-helpers.js`, `src/utils/patterns.js` | 🟢 Completed | 21 / 21 Tests Passing |
| **Babel AST Parser** | `src/engine/ast-parser.js` | 🟢 Completed | 9 / 9 Tests Passing |
| **File Discovery** | `src/engine/file-discovery.js` | 🟢 Completed | 8 / 8 Tests Passing |
| **Rule Auto-Registry** | `src/engine/rule-registry.js` | 🟢 Completed | 5 / 5 Tests Passing |
| **Scanner Orchestrator** | `src/engine/scanner.js` | 🟢 Completed | 7 / 7 Tests Passing |
| **CLI Interface** | `src/cli.js` (Commander.js, ANSI Banner, exit codes) | 🟢 Completed | Verified E2E |
| **Payment Security Rules** | `payment-amount-tampering.js`, `missing-webhook-verification.js` | 🟢 Completed | 18 / 18 Tests Passing |
| **Authentication Rules** | `src/rules/missing-auth-middleware.js` | 🟢 Completed | 8 / 8 Tests Passing |
| **Secrets & Crypto Rules** | `src/rules/hardcoded-secrets.js`, `src/rules/weak-crypto.js` | 🟢 Completed | 22 / 22 Tests Passing |
| **Injection Rules** | `src/rules/sql-injection.js`, `missing-input-validation.js` | 🟢 Completed | 9 / 9 Tests Passing |
| **Reporting & SARIF** | `src/reporters/markdown-reporter.js`, `src/reporters/json-reporter.js` | 🟢 Completed | 14 / 14 Tests Passing |
| **AI & Attack Chains** | `src/ai/enhancer.js` (Offline Heuristics + Multi-LLM) | 🟢 Completed | 8 / 8 Tests Passing |
| **Vulnerable Demo App** | `demo/server.js`, `demo/routes/*`, `demo/db/*` | 🟢 Completed | 8 Canonical Flaws Verified |
| **Hardened Reference App** | `demo-fixed/*` (Verified Remediation Counterpart) | 🟢 Completed | 100% Clean Scan (0 Flaws) |

---

## 💻 Quick Start & CLI Usage

### Prerequisites
- **Node.js**: `20.0.0` or higher
- **npm**: `9.0.0` or higher

### Installation
```bash
# Clone the repository
git clone https://github.com/vikalp1817243/TrustLayer.git
cd TrustLayer

# Install dependencies
npm install
```

### Running the Scanner

TrustLayer features a full-featured CLI powered by Commander.js:

```text
████████╗██████╗ ██╗   ██╗███████╗████████╗██╗      █████╗ ██╗   ██╗███████╗██████╗ 
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
   ██║   ██████╔╝██║   ██║███████╗   ██║   ██║     ███████║ ╚████╔╝ █████╗  ██████╔╝
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗
   ██║   ██║  ██║╚██████╔╝███████║   ██║   ███████╗██║  ██║   ██║   ███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

 🔍 TrustLayer Static Security Scanner v1.0.0
    Deterministic AST & Data-Flow Analysis for Node.js/Express
```

```bash
# 1. Scan current directory (generates terminal table & SECURITY-REPORT.md)
node src/cli.js scan

# 2. Scan a specific project directory
node src/cli.js scan ./demo

# 3. Scan vulnerable demo routes (flags exactly 8 canonical vulnerabilities)
node src/cli.js scan ./demo/routes

# 4. Scan hardened reference application (demonstrates 100% clean scan)
node src/cli.js scan ./demo-fixed

# 5. Scan a single file
node src/cli.js scan ./demo/server.js

# 6. Save report with custom Markdown name & correlated attack chains
node src/cli.js scan ./demo/routes -o audit-summary

# 7. Export structured JSON or OASIS SARIF v2.1.0 for CI/CD pipelines
node src/cli.js scan ./demo/routes -o audit -f json

# 8. Terminal summary only (suppress file output)
node src/cli.js scan ./demo --no-report

# 9. Exclude custom directories from scan
node src/cli.js scan ./demo --ignore "**/fixtures/**"
```

---

## 🧪 Testing

The repository uses **Vitest** for fast unit and integration testing.

```bash
# Run all 133 tests across all 16 test suites
npm test

# Run tests in watch mode during development
npm run test:watch
```

Current test status: **133 passing tests** across 16 test files:
- **Core Engine (29 tests)**:
  - `tests/engine/ast-parser.test.js` (9 tests)
  - `tests/engine/file-discovery.test.js` (8 tests)
  - `tests/engine/rule-registry.test.js` (5 tests)
  - `tests/engine/scanner.test.js` (7 tests)
- **AST Utilities (21 tests)**:
  - `tests/utils/ast-helpers.test.js` (21 tests)
- **Security Rules (57 tests)**:
  - `tests/rules/payment-amount-tampering.test.js` (9 tests)
  - `tests/rules/missing-webhook-verification.test.js` (9 tests)
  - `tests/rules/missing-auth-middleware.test.js` (8 tests)
  - `tests/rules/hardcoded-secrets.test.js` (11 tests)
  - `tests/rules/weak-crypto.test.js` (11 tests)
  - `tests/rules/sql-injection.test.js` (5 tests)
  - `tests/rules/missing-input-validation.test.js` (4 tests)
- **Reporters, AI & E2E Verification (26 tests)**:
  - `tests/reporters/markdown-reporter.test.js` (8 tests)
  - `tests/reporters/json-reporter.test.js` (6 tests)
  - `tests/reporters/enhancer.test.js` (8 tests)
  - `tests/reporters/demo-verification.test.js` (4 tests)

---

## 📚 Documentation & Audits

- 📑 [**Comprehensive Team Audit Report**](docs/audit-report.md) — Detailed technical audit of all 5 members' codebases, test coverage gaps, edge-case analysis, implementation plans, and demo day priorities.
- 🤖 [**AI Agent Directives (AGENTS.md)**](AGENTS.md) — Mandatory architecture rules, non-overlapping file ownership boundaries, and coding standards for AI assistants.
- 👥 [**Team Roles & Ownership (ROLES.md)**](ROLES.md) — Developer responsibility matrix, branch workflows, and merge order.
- 🤝 [**Contributing Guidelines (CONTRIBUTING.md)**](CONTRIBUTING.md) — Contribution protocols, rule interfaces, and pull request checklist.

---

## 📂 Repository Layout

```
TrustLayer/
├── docs/                       # Project documentation & team audits
│   └── audit-report.md         # Comprehensive 5-member codebase audit & implementation plan
├── src/
│   ├── cli.js                  # CLI entrypoint (Commander.js, formatting & exit codes)
│   ├── types/                  # Core data contracts & JSDoc specifications
│   │   ├── rule.js             # Rule and AnalysisContext interfaces
│   │   ├── finding.js          # Finding structure and schema validation
│   │   └── report.js           # ScanReport schema & severity calculators
│   ├── engine/                 # Deterministic scanning engine
│   │   ├── scanner.js          # Orchestrator (scans files, applies rule fallbacks)
│   │   ├── ast-parser.js       # Pure Babel AST parser with error recovery
│   │   ├── file-discovery.js   # Fast glob discovery with default ignore patterns
│   │   └── rule-registry.js    # Dynamic ESM auto-discovery loader
│   ├── rules/                  # Modular security rules (one file per rule)
│   │   ├── payment-amount-tampering.js
│   │   ├── missing-webhook-verification.js
│   │   ├── missing-auth-middleware.js
│   │   ├── hardcoded-secrets.js
│   │   ├── weak-crypto.js
│   │   ├── sql-injection.js
│   │   └── missing-input-validation.js
│   ├── utils/                  # Shared AST traversal and regex pattern libraries
│   │   ├── ast-helpers.js      # isMethodCall, isReqAccess, entropy calculations
│   │   └── patterns.js         # Secret regex definitions & SQL sinks
│   ├── reporters/              # Report generation formats
│   │   ├── markdown-reporter.js# GFM executive report with clean-scan banner
│   │   └── json-reporter.js    # JSON & OASIS SARIF v2.1.0 generator
│   └── ai/                     # Additive AI enhancement
│       └── enhancer.js         # Heuristic attack chains & multi-LLM enrichment
├── demo/                       # Deliberately vulnerable reference Express app
│   ├── server.js               # Express application with route auto-mounting
│   ├── db/setup.js             # SQLite initialization with realistic seeds
│   ├── middleware/auth.js      # Middleware stubs
│   └── routes/                 # 8 canonical vulnerable endpoints (auth, products, checkout, webhook)
├── demo-fixed/                 # Hardened reference app demonstrating verified fixes (0 findings)
├── tests/                      # Automated Vitest test suites (133 tests)
│   ├── engine/                 # Unit tests for core engine modules (29 tests)
│   ├── utils/                  # Unit tests for AST helpers & patterns (21 tests)
│   ├── rules/                  # Rule-specific true positive/negative unit tests (57 tests)
│   └── reporters/              # Reporters, AI enhancer, and E2E demo tests (26 tests)
├── AGENTS.md                   # Global directives for AI assistants
├── ROLES.md                    # Team member role boundaries & ownership guide
├── CONTRIBUTING.md             # Branching protocol and PR guidelines
└── package.json
```

---

## 📐 Rule Specification Contract

Every security rule in `src/rules/*.js` must implement and export the `Rule` interface:

```javascript
/**
 * @typedef {import('../types/rule.js').Rule} Rule
 */

/** @type {Rule} */
const exampleRule = {
  id: 'category/kebab-case-name',
  name: 'Human Readable Title',
  severity: 'critical',           // 'critical' | 'high' | 'medium' | 'low'
  category: 'payment',            // 'payment' | 'auth' | 'injection' | 'secrets'
  description: 'Concise summary of the vulnerability pattern.',
  defaultExplanation: 'In-depth explanation used when AI is offline.',
  defaultRemediation: 'Secure code snippet demonstrating the fix.',
  
  analyze(context) {
    const findings = [];
    const { filePath, fileContent, ast, lines } = context;

    if (!ast) return findings;

    // Use @babel/traverse on the pre-parsed AST
    // Never parse the file manually inside analyze()

    return findings;
  }
};

export default exampleRule;
```

---

## 👥 Team & Ownership Boundaries

To enable parallel development without merge conflicts, team members work in isolated branches:

| Member | Focus Area | Branch | Status | Owned Files |
|---|---|---|:---:|---|
| **Member 1 (Lead)** | Core Engine, CLI, Types, Utils, Tests, Demo Skeleton | `main` | 🟢 Merged | `src/engine/*`, `src/cli.js`, `src/types/*`, `src/utils/*`, `demo/server.js`, `demo/db/*` |
| **Member 2** | Secrets & Weak Cryptography | `feature/secrets-crypto` | 🟢 Merged | `src/rules/hardcoded-secrets.js`, `src/rules/weak-crypto.js`, tests |
| **Member 3** | SQL Injection & Validation Flaws | `feature/injection-rules` | 🟢 Merged | `src/rules/sql-injection.js`, `src/rules/missing-input-validation.js`, tests |
| **Member 4** | Payment Tampering & Auth Gaps | `feature/auth-payment-rules` | 🟢 Merged | `src/rules/payment-*.js`, `src/rules/missing-webhook-*.js`, `missing-auth-*.js`, tests |
| **Member 5** | Reporters, AI Enhancer, Demo Routes & Fixed App | `feature/demo-reporting` | 🟢 Merged | `src/reporters/*`, `src/ai/*`, `demo/routes/*`, `demo-fixed/*`, tests |

For detailed development guidelines, refer to [ROLES.md](ROLES.md) and [AGENTS.md](AGENTS.md).

---

## 📄 License

This project is licensed under the [ISC License](LICENSE).