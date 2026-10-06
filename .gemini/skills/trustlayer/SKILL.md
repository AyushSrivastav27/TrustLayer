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
- **Runtime**: Node.js 20+ / TypeScript 5+
- **Hackathon**: Cybersecurity domain — "Shipped Fast, Left Open"
- **Team**: 5 members, 24–48 hours

## Core Architecture

```
CLI (Commander.js)
  → File Discovery (glob)
    → AST Parsing (@babel/parser + @babel/traverse)
      → Rule Engine (auto-discovered rule modules)
        → Findings
          → AI Enhancement (optional, LLM API)
            → Report Generation (Markdown / JSON)
```

### Key Architectural Principles

1. **Rule auto-discovery**: Rules in `src/rules/*.ts` are auto-loaded. No central registry file.
2. **AI is additive, not foundational**: Scanner MUST work without LLM API. AI only enhances reports.
3. **Single-file scope**: All analysis is intra-file. No cross-file taint tracking.
4. **Express-aware**: Rules understand Express middleware chains, route handlers, `req.*` sources.
5. **E-commerce focus**: Payment security rules (Stripe/Razorpay patterns) are the primary differentiator.

## Repository Structure

```
trustlayer/
├── src/
│   ├── cli.ts                          # CLI entry point (Commander.js)
│   ├── types/
│   │   ├── rule.ts                     # Rule interface (THE contract)
│   │   ├── finding.ts                  # Finding type
│   │   └── report.ts                   # Report type
│   ├── engine/
│   │   ├── scanner.ts                  # Orchestrator
│   │   ├── file-discovery.ts           # Find scannable files
│   │   ├── ast-parser.ts              # Babel AST wrapper
│   │   └── rule-registry.ts           # Auto-load rules from src/rules/
│   ├── rules/                          # One file per rule (isolated modules)
│   │   ├── hardcoded-secrets.ts
│   │   ├── weak-crypto.ts
│   │   ├── sql-injection.ts
│   │   ├── missing-input-validation.ts
│   │   ├── payment-amount-tampering.ts
│   │   ├── missing-webhook-verification.ts
│   │   └── missing-auth-middleware.ts
│   ├── reporters/
│   │   ├── markdown-reporter.ts
│   │   └── json-reporter.ts
│   ├── ai/
│   │   └── enhancer.ts
│   └── utils/
│       ├── ast-helpers.ts
│       └── patterns.ts
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
├── tsconfig.json
├── package.json
└── README.md
```

## The Rule Interface (Critical Contract)

Every security rule MUST implement this interface:

```typescript
export interface Rule {
  id: string;                    // e.g., 'secrets/hardcoded-secret'
  name: string;                  // e.g., 'Hardcoded Secret'
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;              // e.g., 'secrets', 'injection', 'payment', 'auth'
  description: string;
  defaultExplanation: string;    // Used when AI is unavailable
  defaultRemediation: string;    // Used when AI is unavailable

  analyze(context: AnalysisContext): Finding[];
}

export interface AnalysisContext {
  filePath: string;
  fileContent: string;
  ast: ParseResult | null;       // Babel AST (null for non-JS/TS files)
  lines: string[];               // File content split by line
}

export interface Finding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  codeSnippet: string;
  message: string;
  explanation?: string;
  remediation?: string;
  confidence: 'high' | 'medium' | 'low';
}
```

## Coding Conventions

### TypeScript
- Strict mode enabled
- Use `interface` over `type` for public contracts
- Use `const` assertions where appropriate
- No `any` — use `unknown` and narrow
- Export rules as `default export`

### AST Analysis Patterns

Use `@babel/traverse` visitor pattern:
```typescript
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
- Test file location: `tests/rules/<rule-name>.test.ts`
- Test fixtures: `tests/fixtures/`

## File Ownership (Do Not Violate)

| Owner | Files |
|-------|-------|
| Team Lead | `src/engine/`, `src/cli.ts`, `src/types/`, `src/utils/`, `demo/server.js`, `demo/db/` |
| Member 2 | `src/rules/hardcoded-secrets.ts`, `src/rules/weak-crypto.ts`, `tests/rules/hardcoded-secrets.test.ts`, `tests/rules/weak-crypto.test.ts` |
| Member 3 | `src/rules/sql-injection.ts`, `src/rules/missing-input-validation.ts`, `tests/rules/sql-injection.test.ts`, `tests/rules/missing-input-validation.test.ts` |
| Member 4 | `src/rules/payment-amount-tampering.ts`, `src/rules/missing-webhook-verification.ts`, `src/rules/missing-auth-middleware.ts`, `tests/rules/payment-*.test.ts`, `tests/rules/missing-auth-middleware.test.ts` |
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
