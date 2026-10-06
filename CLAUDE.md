# CLAUDE.md — TrustLayer Project Context

## Project Overview

TrustLayer is a CLI-based static security scanner specialized for Node.js/Express e-commerce applications. Built for a 24-48 hour cybersecurity hackathon ("Shipped Fast, Left Open" problem statement).

**Key differentiator**: Payment security rules that no existing SAST tool (Semgrep, MEDUSA, Gitleaks, ESLint-security) implements — client-controlled payment amounts, missing webhook signature verification, insecure payment callbacks.

## Architecture

```
trustlayer scan ./project
  → File Discovery (glob: source .js, .jsx, .mjs, .cjs; config/secrets .json, .env)
    → AST Parsing (@babel/parser with JSX support for JS source files)
      → Rule Engine (auto-discovered from src/rules/*.js)
        → Finding[] (deterministic, reproducible)
          → AI Enhancement (optional LLM: explanation + remediation + attack chains)
            → Report Generation (SECURITY-REPORT.md or JSON)
```

### Non-Negotiable Principles

1. **Scanner MUST produce findings without any LLM API.** AI is enhancement, not detection.
2. **Rules are auto-discovered.** Adding a new `.js` file to `src/rules/` automatically registers it via native ESM `import()`. No central import file.
3. **Single-file scope only.** No cross-file taint tracking. Stay intra-function/intra-file.
4. **Express-framework-aware.** Rules understand `router.get/post()`, middleware chains, `req.body/params/query`.
5. **E-commerce/payment focus.** This is what differentiates us from every generic SAST tool.

## Tech Stack

- Node.js 20+ / Modern JavaScript (ES Modules)
- `@babel/parser` + `@babel/traverse` + `@babel/types` (AST)
- `commander` (CLI)
- `chalk` (colored output)
- `glob` (file discovery)
- `vitest` (testing)
- `express` + `better-sqlite3` (demo app)
- OpenAI/Anthropic SDK (optional AI enhancement)

## Rule Structure Contract

Every rule module in `src/rules/*.js` MUST export a default object:

```javascript
/**
 * @typedef {Object} AnalysisContext
 * @property {string} filePath
 * @property {string} fileContent
 * @property {object|null} ast
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
  category: 'payment',
  description: 'Concise summary',
  defaultExplanation: 'Fallback when AI unavailable',
  defaultRemediation: 'Fallback when AI unavailable',
  analyze(context) {
    const findings = [];
    // AST traversal...
    return findings;
  }
};
```

## Source & Sink Patterns

### Tainted Sources (Express)
```
req.body.*          — POST/PUT body
req.query.*         — URL query parameters
req.params.*        — URL route parameters
req.headers.*       — HTTP headers
Destructured: const { id, amount } = req.body
```

### Critical Sinks
```
// SQL
db.query(), db.run(), db.exec(), db.all(), connection.query(), pool.query()

// Payment APIs (DIFFERENTIATOR)
stripe.charges.create(), stripe.paymentIntents.create()
razorpay.orders.create(), razorpay.payments.capture()

// Execution
eval(), Function(), child_process.exec(), child_process.execSync()
```

## Detection Rules (8 Total)

| Rule | Category | Approach | Priority |
|------|----------|----------|----------|
| Hardcoded Secrets | secrets | Regex + Shannon entropy | MUST |
| Weak Crypto (md5/sha1) | crypto | Function name matching | MUST |
| SQL Injection | injection | AST: template literal + DB call with user input | MUST |
| Unsafe Eval | injection | AST: eval/Function with non-literal argument | MUST |
| Payment Amount Tampering | payment | AST: req.body.amount → payment API sink | MUST (DIFFERENTIATOR) |
| Missing Webhook Signature | payment | AST: webhook route without crypto verification | MUST (DIFFERENTIATOR) |
| Missing Auth Middleware | auth | AST: Express route without auth middleware | MUST |
| IDOR Pattern | auth | AST: req.params.id → DB without user scoping | SHOULD |

## File Ownership Boundaries

**Team Lead owns**: `src/engine/`, `src/cli.js`, `src/types/`, `src/utils/`
**Member 2 owns**: `src/rules/hardcoded-secrets.js`, `src/rules/weak-crypto.js`
**Member 3 owns**: `src/rules/sql-injection.js`, `src/rules/missing-input-validation.js`
**Member 4 owns**: `src/rules/payment-amount-tampering.js`, `src/rules/missing-webhook-verification.js`, `src/rules/missing-auth-middleware.js`
**Member 5 owns**: `src/reporters/`, `src/ai/`, `demo/routes/`, `demo-fixed/`

**RULE: Never modify files you don't own. If you need a change in someone else's file, request it via PR comment.**

## Git Workflow

```
main (protected — team lead only)
├── feature/secrets-config     (Member 2)
├── feature/injection          (Member 3)
├── feature/payment-auth       (Member 4)
└── feature/reporting-ai       (Member 5)
```

Merge order: secrets → injection → payment → reporting

## AST Analysis Patterns for Common Tasks

### Check if a function call matches a pattern
```typescript
function isMethodCall(path: NodePath<CallExpression>, obj: string, method: string): boolean {
  const callee = path.node.callee;
  return (
    callee.type === 'MemberExpression' &&
    callee.object.type === 'Identifier' &&
    callee.object.name === obj &&
    callee.property.type === 'Identifier' &&
    callee.property.name === method
  );
}
```

### Check Express middleware chain
```typescript
// router.get('/path', middleware1, middleware2, handler)
// The handler is the LAST argument. Middlewares are all arguments between path and handler.
traverse(ast, {
  CallExpression(path) {
    if (isExpressRoute(path)) {
      const args = path.node.arguments;
      const middlewares = args.slice(1, -1); // Everything between path and handler
      const hasAuth = middlewares.some(m =>
        m.type === 'Identifier' && AUTH_MIDDLEWARE_NAMES.includes(m.name)
      );
    }
  }
});
```

### Trace user input to sink
```typescript
// For intra-function tracking:
// 1. Find req.body/params/query accesses → mark variable as tainted
// 2. Follow assignments using path.scope.getBinding()
// 3. Check if tainted variable reaches a sink
```

## AI Enhancement Architecture

```
Finding (from static rules)
  → Extract 30-50 lines surrounding code
  → Build prompt: finding metadata + code context + rule info
  → Send to LLM with structured output request
  → Get: explanation, exploitation scenario, remediation code, confidence
  → Merge into finding
  → Optionally: cross-finding correlation for attack chains
```

**Graceful degradation**: If LLM unavailable, use `rule.defaultExplanation` and `rule.defaultRemediation`.

## Demo App: QuickShop

Deliberately vulnerable Express.js e-commerce API with 8 vulnerabilities:
1. Hardcoded JWT secret in `routes/auth.js`
2. SQL injection in `routes/products.js`
3. Missing auth middleware on `routes/orders.js`
4. IDOR in order lookup (no user scoping)
5. Client-controlled payment amount in `routes/checkout.js`
6. Missing webhook signature in `routes/webhook.js`
7. No rate limiting on login
8. Weak password hashing (MD5)

## Testing Requirements

- Framework: Vitest
- Minimum 3 tests per rule: true positive, true negative, edge case
- Test file naming: `tests/rules/<rule-name>.test.js`
- Tests should use inline code strings, not external fixture files when possible

```typescript
import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/sql-injection';
import { parseCode } from '../../src/engine/ast-parser';

describe('sql-injection rule', () => {
  it('detects template literal SQL with user input', () => {
    const code = `
      router.get('/users', (req, res) => {
        db.query(\`SELECT * FROM users WHERE name = '\${req.query.name}'\`);
      });
    `;
    const findings = rule.analyze({
      filePath: 'test.js',
      fileContent: code,
      ast: parseCode(code),
      lines: code.split('\n'),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('ignores parameterized queries', () => {
    const code = `
      router.get('/users', (req, res) => {
        db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
      });
    `;
    const findings = rule.analyze({
      filePath: 'test.js',
      fileContent: code,
      ast: parseCode(code),
      lines: code.split('\n'),
    });
    expect(findings).toHaveLength(0);
  });
});
```

## Common Mistakes

1. ❌ Don't build a generic SAST tool — focus on Express + e-commerce
2. ❌ Don't use AI as the detector — only as report enhancer
3. ❌ Don't try cross-file analysis — impossible in 48 hours
4. ❌ Don't add Semgrep/ESLint as dependencies — we're building our own engine
5. ❌ Don't modify files outside your ownership boundary
6. ❌ Don't claim the tool "proves code is secure" — it identifies common patterns
7. ❌ Don't generate reports without static findings first — AI needs deterministic input
