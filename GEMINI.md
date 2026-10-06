---
name: trustlayer-project
description: >
  TrustLayer hackathon project context and coding standards.
  E-commerce security scanner for Node.js/Express applications.
  Detects payment vulnerabilities, auth gaps, injection flaws, and hardcoded secrets.
---

# TrustLayer — Project Skill (Gemini)

## Project Identity

- **Name**: TrustLayer
- **Type**: CLI-based static security scanner for Node.js/Express e-commerce applications
- **Runtime**: Node.js 20+ / Modern JavaScript (ES Modules)
- **Hackathon**: Cybersecurity domain — "Shipped Fast, Left Open"
- **Team**: 5 members, 24–48 hours

## Core Architecture

```
CLI (Commander.js)
  → File Discovery (glob)
    → AST Parsing (@babel/parser + @babel/traverse)
      → Rule Engine (auto-discovered rule modules via native import())
        → Findings
          → AI Enhancement (optional, LLM API)
            → Report Generation (Markdown / JSON)
```

### Key Architectural Principles

1. **Rule auto-discovery**: Rules in `src/rules/*.js` are auto-loaded. No central registry file.
2. **AI is additive, not foundational**: Scanner MUST work without LLM API. AI only enhances reports.
3. **Single-file scope**: All analysis is intra-file. No cross-file taint tracking.
4. **Express-aware**: Rules understand Express middleware chains, route handlers, `req.*` sources.
5. **E-commerce focus**: Payment security rules (Stripe/Razorpay patterns) are the primary differentiator.

## Repository Structure

```
trustlayer/
├── src/
│   ├── cli.js                          # CLI entry point (Commander.js)
│   ├── types/
│   │   ├── rule.js                     # JSDoc type definitions
│   │   ├── finding.js                  # Finding structure
│   │   └── report.js                   # Report structure
│   ├── engine/
│   │   ├── scanner.js                  # Orchestrator
│   │   ├── file-discovery.js           # Find scannable files
│   │   ├── ast-parser.js              # Babel AST wrapper
│   │   └── rule-registry.js           # Auto-load rules from src/rules/
│   ├── rules/                          # One file per rule (isolated modules)
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
│   │   └── enhancer.js
│   └── utils/
│       ├── ast-helpers.js
│       └── patterns.js
├── demo/                               # Deliberately vulnerable Express app
│   ├── server.js
│   ├── routes/
│   ├── middleware/
│   └── db/
├── demo-fixed/                         # Fixed version for before/after demo
├── tests/
│   ├── rules/
│   ├── engine/
│   └── fixtures/
├── package.json
└── README.md
```

## The Rule Structure (Critical Contract)

Every security rule MUST implement and export this object structure:

```javascript
/**
 * @typedef {Object} AnalysisContext
 * @property {string} filePath
 * @property {string} fileContent
 * @property {object|null} ast - Babel AST
 * @property {string[]} lines
 *
 * @typedef {Object} Finding
 * @property {string} ruleId
 * @property {'critical'|'high'|'medium'|'low'} severity
 * @property {string} file
 * @property {number} line
 * @property {number} [endLine]
 * @property {number} [column]
 * @property {string} codeSnippet
 * @property {string} message
 * @property {string} [explanation]
 * @property {string} [remediation]
 * @property {'high'|'medium'|'low'} confidence
 */

export default {
  id: 'category/rule-name',
  name: 'Human Readable Title',
  severity: 'critical', // 'critical' | 'high' | 'medium' | 'low'
  category: 'payment',  // 'secrets' | 'injection' | 'payment' | 'auth'
  description: 'Concise summary of what pattern is flagged.',
  defaultExplanation: 'Used when AI is unavailable',
  defaultRemediation: 'Used when AI is unavailable',

  /**
   * @param {AnalysisContext} context
   * @returns {Finding[]}
   */
  analyze(context) {
    const findings = [];
    const { filePath, fileContent, ast, lines } = context;
    if (!ast) return findings;
    // AST traversal logic...
    return findings;
  }
};
```

## Coding Conventions

### JavaScript (ESM)
- Node.js 20+ Modern JavaScript with native ES modules (`"type": "module"` in `package.json`).
- Use standard `import` / `export` syntax.
- Use `const` and `let`, avoid `var`.
- No compilation/transpilation step — run directly with `node src/cli.js`.

### AST Analysis Patterns

Use `@babel/traverse` visitor pattern:
```javascript
import traverse from '@babel/traverse';

traverse(ast, {
  CallExpression(path) {
    // Check for db.query() calls
    if (isMethodCall(path, 'db', 'query')) {
      // Check if argument is a template literal with user input
    }
  },
  TemplateLiteral(path) {
    // Check for SQL keywords in template literals
  }
});
```

### Source Patterns (User Input)
These are tainted sources in Express:
- `req.body.*`
- `req.query.*`
- `req.params.*`
- `req.headers.*`
- Destructured: `const { id } = req.params`

### Sink Patterns
- SQL: `db.query()`, `db.run()`, `db.exec()`, `db.all()`, `connection.query()`
- Payment: `stripe.charges.create()`, `stripe.paymentIntents.create()`, `razorpay.orders.create()`
- Execution: `eval()`, `Function()`, `child_process.exec()`

### Testing
- Framework: Vitest
- Each rule must have at least 3 tests: true positive, true negative, edge case
- Test file location: `tests/rules/<rule-name>.test.js`
- Test fixtures: `tests/fixtures/`

## File Ownership (Do Not Violate)

| Owner | Files |
|-------|-------|
| Team Lead | `src/engine/`, `src/cli.js`, `src/types/`, `src/utils/`, `demo/server.js`, `demo/db/` |
| Member 2 | `src/rules/hardcoded-secrets.js`, `src/rules/weak-crypto.js`, `tests/rules/hardcoded-secrets.test.js`, `tests/rules/weak-crypto.test.js` |
| Member 3 | `src/rules/sql-injection.js`, `src/rules/missing-input-validation.js`, `tests/rules/sql-injection.test.js`, `tests/rules/missing-input-validation.test.js` |
| Member 4 | `src/rules/payment-amount-tampering.js`, `src/rules/missing-webhook-verification.js`, `src/rules/missing-auth-middleware.js`, `tests/rules/payment-*.test.js`, `tests/rules/missing-auth-middleware.test.js` |
| Member 5 | `src/reporters/`, `src/ai/`, `demo/routes/`, `demo-fixed/`, `tests/reporters/` |

## Git Workflow

- Main branch: `main` (protected — only team lead merges)
- Feature branches: `feature/secrets-config`, `feature/injection`, `feature/payment-auth`, `feature/reporting-ai`
- PR template: implement Rule interface, only modify owned files, all tests pass
- Merge order: secrets → injection → payment-auth → reporting-ai

## AI Enhancement Architecture

```
Static detection → Finding → Code context (30-50 lines) → LLM prompt → Enhanced finding
```

- AI must NEVER be the primary detector
- Graceful degradation: pre-written default explanations used when LLM unavailable
- AI generates: exploitation scenarios, remediation code, attack chain correlation
- Cache LLM responses for demo reliability

## Payment Security Rules (Differentiator)

These rules are what make TrustLayer unique. No existing SAST tool (Semgrep, MEDUSA, Gitleaks, ESLint-security) has these:

1. **Client-controlled payment amount**: `req.body.amount` → `stripe.charges.create({ amount })`
2. **Missing webhook signature**: Webhook route without `constructEvent()` or `crypto.timingSafeEqual()`
3. **Client-side payment verification**: `req.body.paymentStatus === 'success'` gating order fulfillment
4. **Insecure callback URL**: Payment callback using `http://` instead of `https://`

## Common Mistakes to Avoid

1. ❌ Don't parse files yourself — use the provided AST from `AnalysisContext`
2. ❌ Don't modify `src/engine/` or `src/types/` without team lead approval
3. ❌ Don't add external SAST tools (Semgrep, ESLint) as dependencies — we build our own
4. ❌ Don't use AI as the vulnerability detector — only as report enhancer
5. ❌ Don't try cross-file analysis — stay within single-file scope
6. ❌ Don't flag test files or `node_modules` — file discovery excludes these
