# TrustLayer — Comprehensive Codebase & Architecture Audit Report
**Members 1, 2, 3, 4 & 5 | Engine, Rules, Reporters, AI & Demo**
**Audit Date:** 2026-10-08

---

> [!IMPORTANT]
> **Test Suite Status: ✅ 133/133 tests passing across all 16 test files.** All engine, rule, utility, reporter, and demo verification modules are functional. This audit documents architecture, correctness gaps, bypass opportunities, missing coverage, implementation plans, and demo day priorities across all 5 team members.

---

## Audit Summary Table

| Rule | Owner | Severity | Tests | Detection Completeness | False-Positive Risk | Critical Gaps |
|---|---|---|---|---|---|---|
| `hardcoded-secrets` | Member 2 | Critical | ✅ 9 | 🟡 Medium | 🟡 Medium | Regex patterns unused in rule body |
| `weak-crypto` | Member 2 | High | ✅ 9 | 🟡 Medium | 🟢 Low | Missing `des`/`rc4`, no HMAC check |
| `sql-injection` | Member 3 | Critical | ✅ 5 | 🟡 Medium | 🟢 Low | Misses `connection`, taint not tracked |
| `missing-input-validation` | Member 3 | High | ✅ 4 | 🔴 Low | 🔴 High | Very high FP rate, limited coverage |
| `payment-amount-tampering` | Member 4 | Critical | ✅ 8 | 🟢 High | 🟢 Low | ✅ Excellent implementation |
| `missing-webhook-verification` | Member 4 | High | ✅ 9 | 🟢 High | 🟢 Low | ✅ Solid implementation |
| `missing-auth-middleware` | Member 4 | High | ✅ 7 | 🟢 High | 🟡 Medium | Some FP edge cases |

---

## Member 2 — `hardcoded-secrets.js` & `weak-crypto.js`

### 🔴 Issue M2-1 — `SECRET_PATTERNS` in `patterns.js` is NOT used by the rule

**Severity: High (Logic Inconsistency)**

`src/utils/patterns.js` exports a rich `SECRET_PATTERNS` array with specific regexes for Stripe keys, Razorpay keys, AWS Access Keys, and generic API key patterns. However, [`hardcoded-secrets.js`](file:///home/jay/Documents/TrustLayer/src/rules/hardcoded-secrets.js#L17-L24) defines its own **local, simpler** `SECRET_PATTERNS` using only generic keyword matching (`/apikey/i`, `/secret/i`, etc.). This means:

- ✅ Stripe literal `sk_live_...` IS caught (via `value.startsWith('sk_live_')` hardcoded in the rule).
- ❌ Razorpay keys (`rzp_live_...`) are **NOT caught** — the check only looks for `sk_live_` and `eyJh` prefixes.
- ❌ AWS Access Keys (`AKIA...`) are **NOT caught** at all by the rule logic.
- ❌ Hardcoded Stripe webhook secrets (`whsec_...`) are **NOT caught**.

The `SECRET_PATTERNS` in `patterns.js` that cover all these cases is dead code from the rule's perspective.

**Fix:** Import and use `SECRET_PATTERNS` from `patterns.js` inside `hardcoded-secrets.js`. Add a second detection pass after entropy checking that runs the value against each `SECRET_PATTERNS[n].regex`.

```javascript
// In hardcoded-secrets.js — add this import
import { SECRET_PATTERNS as KNOWN_SECRET_PATTERNS } from '../utils/patterns.js';

// Inside analyze(), after entropy check, add:
const isKnownSecretFormat = KNOWN_SECRET_PATTERNS.some(p => p.regex.test(value));
if (entropy > 3.0 || value.startsWith('sk_live_') || value.startsWith('eyJh') || isKnownSecretFormat) {
  // push finding with higher confidence if isKnownSecretFormat
}
```

---

### 🟡 Issue M2-2 — Rule only catches `VariableDeclarator` and `AssignmentExpression`; misses `ObjectProperty`

**Severity: Medium (Detection Gap)**

A very common pattern in real Express apps is assigning secrets inside object literals passed to SDK constructors:

```javascript
// NOT detected by the current rule
const client = new Stripe({
  apiKey: 'sk_live_abcdefghijklmnop123456',
});
```

The rule only checks `VariableDeclarator` (`const apiKey = '...'`) and `AssignmentExpression` (`obj.apiKey = '...'`). It does not walk `ObjectProperty` nodes inside object expressions.

**Fix:** Add an `ObjectProperty` visitor:
```javascript
ObjectProperty(path) {
  const { key, value } = path.node;
  if (t.isIdentifier(key) && isSecretIdentifier(key.name)) {
    if (t.isStringLiteral(value) && value.value.length >= 5) {
      const entropy = calculateEntropy(value.value);
      if (entropy > 3.0 || ...) { findings.push(...) }
    }
  }
}
```

---

### 🟡 Issue M2-3 — Entropy threshold `3.0` produces false positives on common English words

**Severity: Medium (False Positives)**

An entropy of `3.0` is achieved by relatively normal English strings (e.g., `"password"` has ~2.75, `"administrator"` has ~2.87, `"configuration"` ~3.03). The `'medium'` confidence threshold at `>3.0` and `'high'` at `>4.0` is reasonable, but the rule will flag benign strings like:

```javascript
const secret = 'administrator'; // entropy ≈ 3.03 — flagged!
```

**Fix:** Raise the low-confidence threshold to `3.5` or `require(entropy > 3.0 && value.length > 12)` to reduce noise. Alternatively, add a denylist of common English words to filter out.

---

### 🟡 Issue M2-4 — `weak-crypto.js` misses `des` and `rc4` listed in `WEAK_HASH_ALGORITHMS`

**Severity: Medium (Detection Gap)**

`src/utils/patterns.js` exports:
```javascript
export const WEAK_HASH_ALGORITHMS = ['md5', 'sha1', 'des', 'rc4'];
```

But [`weak-crypto.js`](file:///home/jay/Documents/TrustLayer/src/rules/weak-crypto.js#L30) only checks for `md5` and `sha1`:
```javascript
if (algo === 'md5' || algo === 'sha1') {
```

`DES` and `RC4` are used with `crypto.createCipheriv` (not `createHash`), so they need a separate sink, but the `WEAK_HASH_ALGORITHMS` constant implies they should be covered.

**Fix:** Either update `WEAK_HASH_ALGORITHMS` to clarify it only applies to hashes (not ciphers), OR add a `createCipheriv`/`createCipher` visitor to flag `des` and `rc4`.

---

### 🟡 Issue M2-5 — `Math.random` check requires assignment parent — misses direct function calls

**Severity: Low (Detection Gap)**

The `Math.random` detection in `weak-crypto.js` only fires when `Math.random()` has a parent `VariableDeclarator` or `AssignmentExpression`. This pattern is missed:

```javascript
res.json({ token: Math.random().toString(36) }); // NOT detected
```

The value is still security-sensitive (returned as a token to the client), but it's not assigned to a named variable.

---

### Test Coverage Assessment (Member 2)

| Test File | Count | Missing Scenarios |
|---|---|---|
| `hardcoded-secrets.test.js` | 9 tests | No test for Razorpay/AWS keys, no ObjectProperty test |
| `weak-crypto.test.js` | 9 tests | No test for `des`/`rc4`, no inline return test |

**Action:** Add 2 tests per file for the issues above.

---

## Member 3 — `sql-injection.js` & `missing-input-validation.js`

### 🔴 Issue M3-1 — `sql-injection.js` uses its own `dbObjects` list inconsistent with `patterns.js`

**Severity: Medium (Inconsistency / Gap)**

[`sql-injection.js`](file:///home/jay/Documents/TrustLayer/src/rules/sql-injection.js#L20-L21) defines:
```javascript
const dbMethods = ['query', 'run', 'exec', 'all'];
const dbObjects = ['db', 'connection', 'pool', 'client'];
```

But `patterns.js` exports:
```javascript
export const DB_SINKS = ['query', 'execute', 'exec', 'run', 'all', 'get'];
export const DB_OBJECTS = ['db', 'pool', 'connection', 'client', 'knex', 'sequelize', 'prisma'];
```

Gaps:
- ❌ `execute` (used by `mysql2`) is missing from the rule's `dbMethods`.
- ❌ `get` (sqlite3) is missing.
- ❌ `knex`, `sequelize`, `prisma` are missing from `dbObjects` — these are very common ORMs.

**Fix:** Replace the local arrays with imports:
```javascript
import { DB_SINKS, DB_OBJECTS } from '../utils/patterns.js';
```

---

### 🔴 Issue M3-2 — `sql-injection.js` uses the wrong `traverse` import

**Severity: High (Potential Runtime Error)**

[`sql-injection.js`](file:///home/jay/Documents/TrustLayer/src/rules/sql-injection.js#L1) uses:
```javascript
import traverse from '@babel/traverse';
```

But the rest of the codebase consistently uses the ESM-safe pattern:
```javascript
import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
```

This can silently fail in Node 20 ESM environments where `@babel/traverse` exports its default differently. While tests pass currently, this is a ticking timebomb on different Node/Babel versions.

**Fix:** Change to use the interop pattern like all other rules:
```javascript
import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
```

Same issue exists in `missing-input-validation.js` (line 1).

---

### 🔴 Issue M3-3 — `missing-input-validation.js` has very high false-positive rate

**Severity: High (Usability / Accuracy)**

The rule flags any Express route handler that:
1. Accesses `req.body`, `req.query`, or `req.params`, AND
2. Does NOT call `.validate()`, `.parse()`, `.safeParse()`, `body()`, `query()`, `param()`, or `check()`.

This is extremely broad. **Every real-world Express app will have dozens of legitimate false positives** because:
- Routes that use manual `if (!req.body.field)` guards are not recognized.
- Routes that use `express-validator`'s `validationResult()` flow are not detected.
- Routes that perform `typeof` or `instanceof` checks are not detected.
- Auth routes that just check `req.body.email && req.body.password` will be flagged.

The test suite also confirms only 4 cases — the rule is undercovered for negatives.

**Fix Options:**
1. **Narrow the scope**: Only flag routes where the input goes directly into a DB sink or payment call (correlate with sql-injection findings).
2. **Expand the heuristic**: Also recognize `validationResult`, `if (!req.body.X)` early return guards, `typeof` checks, and manual validation patterns.
3. **Increase confidence to `low`**: Reduce noise by marking all findings as `low` confidence.

---

### 🟡 Issue M3-4 — `missing-input-validation.js` inner `traverse` scope bug

**Severity: Medium (Potential False Negatives)**

The inner traverse at [line 33](file:///home/jay/Documents/TrustLayer/src/rules/missing-input-validation.js#L33):
```javascript
traverse(route.handler, {
  ...
}, path.scope, null, path.parentPath);
```

Passing `route.handler` (a raw AST node, not a `NodePath`) to `traverse()` as the root is non-standard and can cause issues — `traverse` expects either a `File`/`Program` node or a `NodePath` as the second argument when using scope. The fact that it works currently is partly coincidental. The correct pattern is `path.traverse({ ... })` when you want to scope to the current path's subtree.

**Fix:** Use `path.get('arguments').at(-1).traverse({ ... })` or simply loop through the handler's body with explicit guard checks.

---

### 🟡 Issue M3-5 — `sql-injection.js` test file uses raw `@babel/parser` instead of engine's `parseSource`

**Severity: Low (Test Consistency)**

[`sql-injection.test.js`](file:///home/jay/Documents/TrustLayer/tests/rules/sql-injection.test.js#L6-L9) calls `parser.parse()` directly, while all other tests use `parseSource` from `../../src/engine/ast-parser.js`. This means SQL injection tests bypass any parser config that `ast-parser.js` applies (e.g., error recovery, plugin flags), creating a subtle inconsistency.

Same pattern in `missing-input-validation.test.js`.

**Fix:** Change both test files to use the shared `parseSource` helper:
```javascript
import { parseSource } from '../../src/engine/ast-parser.js';
// ...
const { ast } = parseSource(code, 'test.js');
```

---

### Test Coverage Assessment (Member 3)

| Test File | Count | Missing Scenarios |
|---|---|---|
| `sql-injection.test.js` | 5 tests | No `connection.query`, no `sequelize`/`knex` test, no `execute` test |
| `missing-input-validation.test.js` | 4 tests | No negative for manual `if` guard, no test for `validationResult` |

---

## Member 4 — `payment-amount-tampering.js`, `missing-webhook-verification.js`, `missing-auth-middleware.js`

Member 4's work is the most complete and highest quality in the codebase. The rules are well-structured, use proper taint analysis, have good helper function decomposition, and the test suites are comprehensive. Issues found are minor enhancements.

### 🟡 Issue M4-1 — `payment-amount-tampering.js`: `price` key on `req.body` may cause FP

**Severity: Low (False Positive Risk)**

`AMOUNT_KEYS` includes `'price'`. In many APIs, `price` is a catalog ID (e.g., Stripe Price ID), not a numeric amount. A pattern like:

```javascript
stripe.paymentIntents.create({ price: req.body.priceId }); // legitimate!
```

…would be flagged as tampering, even though `price` here is a product ID, not an amount. The rule currently has no way to distinguish.

**Fix:** Consider removing `'price'` from `AMOUNT_KEYS` unless the value is a number, or check that the value is used in a numeric context (e.g., it goes through `Number()` or arithmetic).

---

### 🟡 Issue M4-2 — `missing-webhook-verification.js`: `NON_EXPRESS_OBJECTS` duplicated

**Severity: Low (Code Duplication / Maintainability)**

Both [`missing-webhook-verification.js`](file:///home/jay/Documents/TrustLayer/src/rules/missing-webhook-verification.js#L99-L104) and [`missing-auth-middleware.js`](file:///home/jay/Documents/TrustLayer/src/rules/missing-auth-middleware.js#L79-L84) define identical `NON_EXPRESS_OBJECTS` sets:
```javascript
const NON_EXPRESS_OBJECTS = new Set([
  'db', 'pool', 'connection', 'client', 'knex', ...
]);
```

This should be a shared utility exported from `src/utils/ast-helpers.js` or `src/utils/patterns.js`.

**Fix:** Export `NON_EXPRESS_OBJECTS` from `patterns.js` and import it in both rules.

---

### 🟡 Issue M4-3 — `missing-auth-middleware.js`: router-level auth pass doesn't track `app` object

**Severity: Low (False Negative)**

The `protectedRouters` set tracks auth via `router.use(authenticate)` but doesn't handle the case where `app.use('/api', authenticate)` is called. If authentication is applied at the app-level with a path prefix, individual routes below that prefix will still be flagged.

```javascript
app.use('/api', authenticate); // applied globally
app.get('/api/orders', handler); // falsely flagged as unprotected
```

---

### ✅ Strengths (Member 4)

- `isTaintedByClient()` correctly handles destructuring, binary expressions, type casts, and scope resolution — this is the most sophisticated analysis in the codebase.
- `isPaymentSinkCall()` correctly handles 2-level and 3-level method chains (e.g., `stripe.checkout.sessions.create`).
- `containsSignatureVerification()` correctly traverses handler body + resolves identifier references to function declarations.
- `isValidExpressRoute()` correctly filters out false route matches from DB/HTTP client calls.
- All three tests have comprehensive true-positive, true-negative, and edge-case coverage.

---

## Implementation Plan

### Priority 1 — Must Fix (Correctness / Security Gaps)

| ID | Task | File | Owner |
|---|---|---|---|
| P1-A | Use shared `SECRET_PATTERNS` from `patterns.js`; add Razorpay/AWS detection | `src/rules/hardcoded-secrets.js` | Member 2 |
| P1-B | Add `ObjectProperty` visitor for secrets inside object literals | `src/rules/hardcoded-secrets.js` | Member 2 |
| P1-C | Fix `traverse` import to use ESM interop pattern | `src/rules/sql-injection.js`, `src/rules/missing-input-validation.js` | Member 3 |
| P1-D | Replace local `dbMethods`/`dbObjects` with `DB_SINKS`/`DB_OBJECTS` from `patterns.js` | `src/rules/sql-injection.js` | Member 3 |

### Priority 2 — Should Fix (Quality / Coverage)

| ID | Task | File | Owner |
|---|---|---|---|
| P2-A | Add `des`/`rc4` cipher detection via `createCipheriv` visitor | `src/rules/weak-crypto.js` | Member 2 |
| P2-B | Raise entropy threshold to reduce false positives | `src/rules/hardcoded-secrets.js` | Member 2 |
| P2-C | Reduce false-positive rate of missing-input-validation (add `validationResult`, `if` guards) | `src/rules/missing-input-validation.js` | Member 3 |
| P2-D | Extract `NON_EXPRESS_OBJECTS` to shared `patterns.js` | `src/utils/patterns.js` | Member 4 / Team Lead |

### Priority 3 — Nice to Have (Enhancements)

| ID | Task | File | Owner |
|---|---|---|---|
| P3-A | Add tests for Razorpay/AWS keys in hardcoded-secrets | `tests/rules/hardcoded-secrets.test.js` | Member 2 |
| P3-B | Add `connection.execute`, `sequelize.query` tests for sql-injection | `tests/rules/sql-injection.test.js` | Member 3 |
| P3-C | Migrate test helpers to use shared `parseSource` | Both M3 test files | Member 3 |
| P3-D | Handle `app.use('/prefix', auth)` in missing-auth-middleware | `src/rules/missing-auth-middleware.js` | Member 4 |
| P3-E | Narrow `price` key in `AMOUNT_KEYS` to numeric-only contexts | `src/utils/patterns.js` | Member 4 |

---

## Member 5 — `src/reporters/`, `src/ai/enhancer.js`, `demo/routes/`, `demo-fixed/`, `tests/reporters/`

**Test Suite Status: ✅ 26/26 tests passing across 4 test files.**

Member 5's scope is the largest and most cross-cutting: report generation (Markdown + JSON/SARIF), the AI enhancement layer, the vulnerable demo application, the hardened `demo-fixed` counterpart, and the end-to-end integration tests. The overall quality is high, but there are meaningful gaps in all subsystems worth addressing.

---

### 📊 Member 5 File Inventory

| File | Status | Test Coverage |
|---|---|---|
| [`src/reporters/markdown-reporter.js`](file:///home/jay/Documents/TrustLayer/src/reporters/markdown-reporter.js) | ✅ Implemented | 8 tests |
| [`src/reporters/json-reporter.js`](file:///home/jay/Documents/TrustLayer/src/reporters/json-reporter.js) | ✅ Implemented | 6 tests |
| [`src/ai/enhancer.js`](file:///home/jay/Documents/TrustLayer/src/ai/enhancer.js) | ✅ Implemented | 8 tests |
| [`demo/routes/auth.js`](file:///home/jay/Documents/TrustLayer/demo/routes/auth.js) | ✅ Vulnerable demo | E2E tested |
| [`demo/routes/checkout.js`](file:///home/jay/Documents/TrustLayer/demo/routes/checkout.js) | ✅ Vulnerable demo | E2E tested |
| [`demo/routes/orders.js`](file:///home/jay/Documents/TrustLayer/demo/routes/orders.js) | ✅ Vulnerable demo | E2E tested |
| [`demo/routes/products.js`](file:///home/jay/Documents/TrustLayer/demo/routes/products.js) | ✅ Vulnerable demo | E2E tested |
| [`demo/routes/webhook.js`](file:///home/jay/Documents/TrustLayer/demo/routes/webhook.js) | ✅ Vulnerable demo | E2E tested |
| [`demo/middleware/auth.js`](file:///home/jay/Documents/TrustLayer/demo/middleware/auth.js) | ✅ Implemented | E2E tested |
| [`demo-fixed/routes/`](file:///home/jay/Documents/TrustLayer/demo-fixed/routes) | ✅ Hardened | E2E tested |
| `tests/reporters/` | ✅ 4 test files | 26 tests total |

---

### 🔴 Issue M5-1 — `markdown-reporter.js` imports `correlateAttackChains` and `getDeterministicScenario` but creates a circular-ish coupling

**Severity: Medium (Architecture)**

[`markdown-reporter.js` line 2](file:///home/jay/Documents/TrustLayer/src/reporters/markdown-reporter.js#L2) imports directly from `enhancer.js`:
```javascript
import { correlateAttackChains, getDeterministicScenario } from '../ai/enhancer.js';
```

This creates a tight coupling between the reporter and the AI layer. The architectural intent (as stated in GEMINI.md and the implementation plan) is:
```
Static detection → Finding → AI Enhancement → Report
```

The reporter should receive an already-enhanced report — it should not be calling AI functions internally. If `enhanceReport()` is called before generating the markdown, the reporter will call `correlateAttackChains()` a **second time** (on line 74), potentially producing duplicate chains if the report already has `attackChains` populated.

**Fix:** Remove the internal `correlateAttackChains` call from the reporter. The `if (activeChains.length === 0 && typeof correlateAttackChains === 'function')` fallback block (lines 72–78) should be removed — the CLI pipeline should always call `enhanceReport()` before generating the markdown. This keeps the reporter as a pure presentation layer.

---

### 🔴 Issue M5-2 — `demo/routes/checkout.js`: Stripe key is initialised with a fallback that looks like a real key prefix

**Severity: Medium (Demo Correctness / False Negative Risk)**

[`demo/routes/checkout.js` line 5](file:///home/jay/Documents/TrustLayer/demo/routes/checkout.js#L5):
```javascript
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder_key_123');
```

The fallback string `'sk_test_placeholder_key_123'` starts with `sk_test_` — this will be flagged by `hardcoded-secrets.js` as a detected secret even though it is intentionally a placeholder. The demo is supposed to show 8 canonical vulnerabilities (3 critical, 5 high), and the `demo-verification.test.js` confirms exactly that count. But this line is a false-positive-producing secret that the rule would also flag inside the vulnerable app in real usage — it pollutes the finding count and weakens the demo story.

The same pattern exists in `demo-fixed/routes/checkout.js` (line 9) and `demo-fixed/routes/webhook.js` (line 7). If the hardcoded-secrets rule is enhanced (as recommended in M2-1), these lines will start generating findings in the "clean" demo-fixed scan, breaking the `0 findings` contract in `demo-verification.test.js`.

**Fix:** Use `process.env.STRIPE_SECRET_KEY` without a fallback in demo routes, or use a clearly non-realistic placeholder like `'stripe_key_not_configured'` that won't match the `sk_test_` prefix.

---

### 🔴 Issue M5-3 — `demo-fixed/routes/auth.js` has a double-hashing inconsistency (login doesn't use salt)

**Severity: Medium (Security Logic Bug in Fixed Demo)**

In [`demo-fixed/routes/auth.js`](file:///home/jay/Documents/TrustLayer/demo-fixed/routes/auth.js), the `/register` endpoint correctly generates a salt and hashes `password + salt`:
```javascript
const salt = crypto.randomBytes(16).toString('hex');
const passwordHash = crypto.createHash('sha256').update(password + salt).digest('hex');
```

But the `/login` endpoint at line 57 hashes **without the salt**:
```javascript
const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
```

This means **login will never succeed** for any registered user in the fixed demo, because the stored hash (with salt) will never match the login hash (without salt). This is a serious logic bug in the "hardened" version of the app that undermines the demo story of "fixed code works correctly."

Additionally, the salt is generated but not stored — there is no `salt` column in the DB schema, so even fixing the login would require a schema migration.

**Fix:** Either use a salted-hash comparison library like `bcrypt`/`argon2`, or store the salt in the DB alongside the hash and retrieve it during login before comparing.

---

### 🟡 Issue M5-4 — `json-reporter.js` (`toSarif`) doesn't include `endColumn` in region

**Severity: Low (SARIF Spec Completeness)**

The SARIF output in [`json-reporter.js`](file:///home/jay/Documents/TrustLayer/src/reporters/json-reporter.js#L48-L56) populates the `region` with `startLine`, `startColumn`, and `endLine`, but not `endColumn`. The SARIF 2.1.0 spec recommends providing `endColumn` for precise code highlighting in GitHub Code Scanning's inline view.

```javascript
region: {
  startLine: f.line || 1,
  startColumn: f.column || 1,
  endLine: f.endLine || f.line || 1
  // Missing: endColumn
}
```

**Fix:** Add `endColumn: f.endColumn || undefined` to the region object.

---

### 🟡 Issue M5-5 — `enhancer.js`: LLM cache is module-level (persists across test runs in watch mode)

**Severity: Low (Test Reliability)**

The `LLM_CACHE` Map at [line 102](file:///home/jay/Documents/TrustLayer/src/ai/enhancer.js#L102) is a module-level singleton:
```javascript
const LLM_CACHE = new Map();
```

In Vitest's watch mode, module state is preserved between test re-runs because modules are cached. A test that sets a cache entry via a mock API key will "poison" subsequent test runs, potentially making them return stale data and masking bugs.

**Fix:** Export a `clearCache()` function for test teardown:
```javascript
export function clearCache() { LLM_CACHE.clear(); }
```
And call it in `afterEach` in `enhancer.test.js`.

---

### 🟡 Issue M5-6 — `enhancer.js` OpenAI branch checks `apiKey.startsWith('sk-')` but OpenAI changed key format

**Severity: Low (Future Compatibility)**

The OpenAI API branch at [line 242](file:///home/jay/Documents/TrustLayer/src/ai/enhancer.js#L242):
```javascript
} else if (process.env.OPENAI_API_KEY || (apiKey && apiKey.startsWith('sk-'))) {
```

OpenAI deprecated the `sk-` key prefix in 2024 in favor of `sk-proj-` and `sk-org-` prefixes. The `startsWith('sk-')` check still works but is fragile — a key starting with `sk-proj-` passes this check, but an organization key `sk-org-...` may not match if the check is tightened in the future.

**Fix:** Check `process.env.OPENAI_API_KEY` only (rely on the env var being set), or use a more permissive `apiKey.startsWith('sk-')` with a comment noting this handles all current OpenAI key formats.

---

### 🟡 Issue M5-7 — `demo/routes/products.js` SQL injection uses `db.all()` but `dbObjects` in `sql-injection.js` checks for `db`

**Severity: Low (Demo Alignment)**

[`demo/routes/products.js` line 35](file:///home/jay/Documents/TrustLayer/demo/routes/products.js#L35):
```javascript
const results = db.all(`SELECT * FROM products WHERE name LIKE '%${q}%'`);
```

The `sql-injection.js` rule's `dbObjects` list includes `db` and its `dbMethods` includes `all`. This is correctly detected. However, the DB call is made directly on the `db` object (sqlite3/better-sqlite3 style) without `.prepare()`, which is a slightly different pattern than what most of the test cases cover. Currently this works, but it is a reminder that the E2E test is validating the demo works — not that all code paths in the rule are exercised.

---

### 🟡 Issue M5-8 — `demo-verification.test.js` expects exactly 8 findings — fragile as rules improve

**Severity: Medium (Test Brittleness)**

[`demo-verification.test.js` line 34](file:///home/jay/Documents/TrustLayer/tests/reporters/demo-verification.test.js#L34):
```javascript
expect(report.findings).toHaveLength(8);
```

This is an exact count assertion. As rules improve (e.g., after M2-1 fixes add Razorpay/AWS detection), the demo's `hardcoded-secrets` rule may start producing more than 1 finding (e.g., the `sk_test_placeholder_key_123` in checkout.js could be flagged). The E2E count will silently break.

**Fix:** Use `toBeGreaterThanOrEqual(8)` or carefully document which exact 8 vulnerabilities are expected in a comment, and update the demo files alongside rule changes.

---

### 🟡 Issue M5-9 — `markdown-reporter.js` calls `path.relative(process.cwd(), f.file)` — breaks on relative paths

**Severity: Low (Edge Case Bug)**

At [line 104](file:///home/jay/Documents/TrustLayer/src/reporters/markdown-reporter.js#L104) and [line 119](file:///home/jay/Documents/TrustLayer/src/reporters/markdown-reporter.js#L119):
```javascript
const relFile = f.file ? (path.relative(process.cwd(), f.file) || f.file) : 'unknown';
```

If `f.file` is already a relative path (e.g., `routes/checkout.js` as returned from some scan modes), `path.relative(cwd, relative_path)` will produce a mangled result like `../../routes/checkout.js`. The fallback `|| f.file` only triggers if `path.relative` returns an empty string (i.e., when `f.file === cwd`), not when it returns a longer wrong path.

**Fix:**
```javascript
const relFile = f.file
  ? (path.isAbsolute(f.file) ? path.relative(process.cwd(), f.file) : f.file)
  : 'unknown';
```

---

### ✅ Strengths (Member 5)

- **SARIF output** (`toSarif`) is well-structured and correct for GitHub Code Scanning integration — maps `critical/high` to `error`, `medium` to `warning`, `low` to `note`, and populates the `rules` array from deduped `ruleId`s.
- **Graceful degradation** in `enhanceFinding()` is correct — deterministic heuristics fire immediately without an API key, the LLM call is wrapped in a 5-second `AbortSignal.timeout`, errors are swallowed silently, and the base enhanced finding is always returned.
- **Attack chain correlation** (`correlateAttackChains`) is a standout feature — deterministic heuristic chaining without any LLM dependency, correctly covering all 4 compound scenarios.
- **Demo app design** is excellent for hackathon purposes — each file targets a specific vulnerability with clear comments (`🔴 VULNERABILITY #N`), and the demo-fixed counterpart shows the correct remediation side-by-side.
- **Pipe-escaping in markdown** (line 109 of reporter) correctly prevents GFM table corruption for messages containing `|`.
- **Dual-fence code block handling** (line 132) intelligently switches to `````````javascript when the snippet itself contains triple backticks.
- **`demo-verification.test.js`** is a particularly strong test — it runs a true end-to-end scan from file discovery → AST parsing → rule application → AI enhancement → markdown rendering, covering the entire pipeline in 4 tests.

---

### Test Coverage Assessment (Member 5)

| Test File | Count | Missing Scenarios |
|---|---|---|
| `markdown-reporter.test.js` | 8 tests | No test for relative path handling bug (M5-9); no test for reporter called pre-enhancement with empty `attackChains` |
| `json-reporter.test.js` | 6 tests | No test for `endColumn` in SARIF; no test for findings without `column` field |
| `enhancer.test.js` | 8 tests | No `clearCache()` teardown; no test for Gemini vs OpenAI branch selection |
| `demo-verification.test.js` | 4 tests | Exact count `toHaveLength(8)` is fragile; no test for partial scan errors |

---

### Member 5 Implementation Plan

| Priority | Task | File |
|---|---|---|
| P1 | Fix salt-inconsistency in `demo-fixed/routes/auth.js` login (critical logic bug) | `demo-fixed/routes/auth.js` |
| P1 | Remove `correlateAttackChains` call from inside `markdown-reporter.js`; make reporter a pure presenter | `src/reporters/markdown-reporter.js` |
| P2 | Replace `sk_test_placeholder_key_123` fallbacks with non-key-like strings in demo + demo-fixed | `demo/routes/checkout.js`, `demo-fixed/routes/checkout.js`, `demo-fixed/routes/webhook.js` |
| P2 | Fix `path.relative` absolute-vs-relative path bug in markdown reporter | `src/reporters/markdown-reporter.js` |
| P2 | Add `endColumn` field to SARIF region output | `src/reporters/json-reporter.js` |
| P3 | Export `clearCache()` from `enhancer.js` and call in test `afterEach` | `src/ai/enhancer.js`, `tests/reporters/enhancer.test.js` |
| P3 | Change `toHaveLength(8)` to `toBeGreaterThanOrEqual(8)` in demo-verification | `tests/reporters/demo-verification.test.js` |

---

## Overall Health (All Members)

```
Member 2 (Secrets/Crypto):  🟡 Functional but has correctness gap (unused patterns, missing prefix checks)
Member 3 (Injection):       🔴 Rule body works but high FP risk + import inconsistency — needs attention
Member 4 (Auth/Payment):    🟢 Best quality in rules codebase — minor DRY and edge case fixes only
Member 5 (Reporting/Demo):  🟡 Strong foundation — reporter architecture coupling, demo auth logic bug, brittle E2E count
```

### Cross-Member Priority Fix Order (Recommended for Demo Day)

1. **M3-2** — Fix `traverse` import in `sql-injection.js` / `missing-input-validation.js` (silent runtime risk)
2. **M5-3** — Fix `demo-fixed` login salting bug (breaks the demo story)
3. **M2-1** — Wire `SECRET_PATTERNS` from `patterns.js` into the rule (Razorpay/AWS detection gap)
4. **M5-1** — Decouple reporter from AI enhancer (architectural correctness)
5. **M5-2** — Replace `sk_test_placeholder_key_123` fallbacks before demo
6. **M3-1** — Import `DB_SINKS`/`DB_OBJECTS` from `patterns.js` in sql-injection rule
7. **M5-8** — Relax `toHaveLength(8)` assertion before rule improvements trigger breaks

---

## Member 1 (Team Lead) — `src/engine/`, `src/cli.js`, `src/types/`, `src/utils/`, `demo/server.js`, `demo/db/`

**Test Suite Status: ✅ 29/29 engine tests passing + 13/13 utils/patterns tests passing.**

Member 1 owns the foundation everything else depends on: the scan pipeline, CLI entry point, AST parsing, rule auto-discovery, file discovery, type contracts, and the shared utility library. This is the highest-risk code in the project — a bug here affects all 7 rules and both reporters simultaneously. The implementation is clean and well-structured, but there are notable gaps in completeness, edge handling, and CLI reliability.

---

### 📊 Member 1 File Inventory

| File | Status | Test Coverage |
|---|---|---|
| [`src/engine/scanner.js`](file:///home/jay/Documents/TrustLayer/src/engine/scanner.js) | ✅ Implemented | 7 tests |
| [`src/engine/file-discovery.js`](file:///home/jay/Documents/TrustLayer/src/engine/file-discovery.js) | ✅ Implemented | 7 tests |
| [`src/engine/ast-parser.js`](file:///home/jay/Documents/TrustLayer/src/engine/ast-parser.js) | ✅ Implemented | 8 tests |
| [`src/engine/rule-registry.js`](file:///home/jay/Documents/TrustLayer/src/engine/rule-registry.js) | ✅ Implemented | 5 tests |
| [`src/cli.js`](file:///home/jay/Documents/TrustLayer/src/cli.js) | ✅ Implemented | ❌ 0 tests |
| [`src/types/rule.js`](file:///home/jay/Documents/TrustLayer/src/types/rule.js) | ✅ JSDoc types | ✅ Referenced in tests |
| [`src/types/finding.js`](file:///home/jay/Documents/TrustLayer/src/types/finding.js) | ✅ Types + factory | ❌ 0 direct tests |
| [`src/types/report.js`](file:///home/jay/Documents/TrustLayer/src/types/report.js) | ✅ Types + helper | ✅ Used in scanner tests |
| [`src/utils/ast-helpers.js`](file:///home/jay/Documents/TrustLayer/src/utils/ast-helpers.js) | ✅ Implemented | 13 tests |
| [`src/utils/patterns.js`](file:///home/jay/Documents/TrustLayer/src/utils/patterns.js) | ✅ Implemented | 3 pattern tests |
| [`demo/server.js`](file:///home/jay/Documents/TrustLayer/demo/server.js) | ✅ Implemented | E2E tested |
| [`demo/db/setup.js`](file:///home/jay/Documents/TrustLayer/demo/db/setup.js) | ✅ Implemented | E2E tested |

---

### 🔴 Issue M1-1 — `cli.js` has zero unit tests — highest-risk untested code

**Severity: High (Testing Gap)**

The CLI at [`src/cli.js`](file:///home/jay/Documents/TrustLayer/src/cli.js) is 276 lines with critical control-flow logic:
- Path validation and exit codes (`process.exit(2)` on bad target)
- Format validation and report routing
- `resolveReportTarget()` — format inference from file extension
- `--no-report` flag handling
- CI exit code contract: exits `1` on critical/high, `0` on clean scan

None of this is covered by any test. A regression in `resolveReportTarget()` or the exit-code logic would silently break CI integration for every downstream user.

**Fix:** Add a `tests/cli.test.js` using Vitest's `exec` or by unit-testing the exported helper functions. At minimum, `resolveReportTarget` should be exported and tested directly:
```javascript
// Suggested test cases
resolveReportTarget(null, 'json')      // → { format: 'json', filePath: '...security-report.json' }
resolveReportTarget('audit', 'json')   // → { format: 'json', filePath: '...audit.json' }
resolveReportTarget('report.md', 'json') // → { format: 'markdown', filePath: '...report.md' }
```

---

### 🔴 Issue M1-2 — `cli.js` contains a duplicate `generateMarkdownReport` function — shadow of Member 5's reporter

**Severity: Medium (Code Duplication / Correctness)**

[`cli.js` lines 81–122](file:///home/jay/Documents/TrustLayer/src/cli.js#L81-L122) defines its own `generateMarkdownReport()` as a fallback. This local version is significantly less complete than Member 5's [`markdown-reporter.js`](file:///home/jay/Documents/TrustLayer/src/reporters/markdown-reporter.js):

- Missing: attack chain section, SEVERITY_BADGES with coloured emoji, per-finding code fence safety, executive summary table format.
- Uses `finding.severity.toUpperCase()` on line 101 **without null-guarding** — crashes if `finding.severity` is `undefined`.

The CLI does attempt to dynamically import the real reporter first (lines 246–256), but the fallback path means if the real reporter ever fails to load, users silently get an inferior incomplete report with no warning except a `console.warn`-less silent catch.

**Fix:** Remove the local fallback entirely. If the import fails, the CLI should log a clear error and exit. The `markdown-reporter.js` should be treated as a hard dependency, not an optional one.

---

### 🟡 Issue M1-3 — `scanner.js` runs rules sequentially — no parallelism within a file

**Severity: Low (Performance)**

[`scanner.js` line 80](file:///home/jay/Documents/TrustLayer/src/engine/scanner.js#L80) processes files sequentially in a `for` loop. Within each file, rules are also applied sequentially (line 31). For large codebases, this is significantly slower than necessary.

The per-rule `analyze()` functions are synchronous (they return `Finding[]`, not `Promise<Finding[]>`), so intra-file rule parallelism via `Promise.all` is safe:

```javascript
// Current sequential approach
for (const rule of rules) { ... }

// Faster parallel approach
const perRuleFindings = await Promise.all(rules.map(rule => {
  try { return rule.analyze(context); } catch { ... return []; }
}));
const fileFindings = perRuleFindings.flat();
```

At hackathon scale (few files) this doesn't matter, but it's worth noting for the demo's "enterprise scanning" narrative.

---

### 🟡 Issue M1-4 — `ast-parser.js` does not pass `filePath` to the parser — location context may be wrong in error reporting

**Severity: Low (Missing Feature)**

[`ast-parser.js`](file:///home/jay/Documents/TrustLayer/src/engine/ast-parser.js) accepts `filePath` as a parameter but never uses it:

```javascript
export function parseSource(sourceCode, filePath = '') {
  // filePath is accepted but never passed to babelParser.parse()
  const ast = babelParser.parse(sourceCode, {
    sourceType: 'unambiguous',
    plugins: ['jsx'],
    errorRecovery: true
  });
```

Babel's parser accepts a `plugins: [..., ['babel-plugin-...', { sourceFilename: filePath }]]` or the parse options can include it, but more importantly — when `ast.errors` contains parse errors and they're surfaced in findings, the error won't have a meaningful file reference.

**Fix:** Minor but clean:
```javascript
// Could log parse errors with the filePath for diagnostics:
if (ast.errors && ast.errors.length > 0) {
  // optionally warn with filePath context
}
```

---

### 🟡 Issue M1-5 — `rule-registry.js` does not validate rule `severity` or `category` fields

**Severity: Low (Robustness)**

[`rule-registry.js` line 23](file:///home/jay/Documents/TrustLayer/src/engine/rule-registry.js#L23) only validates that a rule has an `id` and an `analyze` function:

```javascript
if (rule && rule.id && typeof rule.analyze === 'function') {
  rules.push(rule);
}
```

A rule that passes this check but has `severity: 'ultra-critical'` (an invalid value not in the type contract) or no `defaultExplanation` would silently break the `calculateSeverityCounts()` function in `report.js` — the severity count for that finding would never increment because `counts['ultra-critical']` is `undefined`.

**Fix:** Add validation against the `Rule` contract:
```javascript
const validSeverities = ['critical', 'high', 'medium', 'low'];
const validCategories = ['secrets', 'injection', 'payment', 'auth'];

if (rule && rule.id && typeof rule.analyze === 'function'
  && validSeverities.includes(rule.severity)
  && validCategories.includes(rule.category)) {
  rules.push(rule);
} else {
  console.warn(`[TrustLayer] Rule at ${filePath} failed contract validation.`);
}
```

---

### 🟡 Issue M1-6 — `demo/db/setup.js` seeds plaintext passwords into the database

**Severity: Medium (Demo Integrity)**

[`demo/db/setup.js` lines 62–78](file:///home/jay/Documents/TrustLayer/demo/db/setup.js#L62-L78) inserts seed users with plaintext passwords:

```javascript
insertUser.run({ name: 'System Administrator', email: 'admin@quickshop.com', password: 'admin_password_hash_123', role: 'admin' });
insertUser.run({ name: 'Alice Johnson', email: 'alice@example.com', password: 'password123', role: 'user' });
```

The column is named `password` and the values look like plaintext strings (despite one being named `_hash_`). The vulnerable demo's `auth.js` uses MD5 for registration, but the seed data bypasses this — the demo users can't actually authenticate through the vulnerable API since there's no matching MD5 hash.

This doesn't break any test (the E2E tests don't test auth login flow), but it weakens the demo's believability during a live demo session.

**Fix:** Pre-hash the seed passwords with MD5 to match what the vulnerable `auth.js` produces:
```javascript
import crypto from 'node:crypto';
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
insertUser.run({ ..., password: md5('admin123') });
```

---

### 🟡 Issue M1-7 — `file-discovery.js` does not handle `targetPath` that doesn't exist — no early error

**Severity: Low (Robustness)**

[`file-discovery.js` line 26](file:///home/jay/Documents/TrustLayer/src/engine/file-discovery.js#L26):
```javascript
if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isFile()) {
  return [resolvedPath];
}
```

If `resolvedPath` is a file, it's returned. If it's a directory, `glob` is run. But if `resolvedPath` doesn't exist at all — the `existsSync` check fails, `statSync` is never called, and `glob` runs on a non-existent directory. `glob` returns `[]` silently rather than an error.

This means `scan('/path/that/doesnt/exist')` completes with `{ totalFiles: 0, findings: [] }` instead of throwing. The CLI guards against this (line 160), but calling `scan()` programmatically bypasses the guard.

**Fix:**
```javascript
if (!fs.existsSync(resolvedPath)) {
  throw new Error(`Target path does not exist: ${resolvedPath}`);
}
```

---

### 🟡 Issue M1-8 — `scanner.js` reports `scannerVersion: '1.0.0'` as a hardcoded string

**Severity: Low (Maintainability)**

[`scanner.js` line 99](file:///home/jay/Documents/TrustLayer/src/engine/scanner.js#L99):
```javascript
return { scannerVersion: '1.0.0', ... };
```

The version is also hardcoded in `cli.js` line 33 (`v1.0.0`), `cli.js` line 138 (Commander `.version('1.0.0')`), and the markdown reporter. If the version is bumped in `package.json`, 4 separate places need to be updated manually.

**Fix:** Import the version from `package.json`:
```javascript
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { version } = require('../../package.json');
// or use: import pkg from '../../package.json' with assert { type: 'json' }
```

---

### 🟡 Issue M1-9 — `types/finding.js` `createFinding()` factory is unused across the entire codebase

**Severity: Low (Dead Code)**

[`finding.js` lines 33–53](file:///home/jay/Documents/TrustLayer/src/types/finding.js#L33-L53) exports a `createFinding()` factory with validation:
```javascript
export function createFinding(finding) {
  if (!finding.ruleId || !finding.file || typeof finding.line !== 'number') {
    throw new Error('Finding requires ruleId, file, and line properties.');
  }
  ...
}
```

A search across the entire codebase shows **no rule, no scanner, no test** ever calls `createFinding()`. All rules push raw finding objects directly. This means the validation contract defined in the type system is never enforced at runtime — a rule could omit `file` or `line` and it would only surface as a malformed display in the report, not as an error.

**Fix:** Either delete `createFinding()` (dead code), or have `scanner.js` call it during the finding normalization step (lines 37–49) to enforce the contract at scan time.

---

### ✅ Strengths (Member 1)

- **Rule auto-discovery** via dynamic `import()` + `pathToFileURL` is exactly right for Node 20 ESM. No hardcoded rule registry needed — adding a new `.js` file to `src/rules/` is sufficient.
- **Error isolation** in `scanFile()` (try/catch per rule) is a critical correctness feature — a crashing rule cannot halt the entire scan. Well tested.
- **`errorRecovery: true`** in the parser means even syntactically broken JS files yield a partial AST rather than a null scan — maximizes coverage.
- **`calculateSeverityCounts()`** in `report.js` is a clean pure function, correctly tested via the scanner suite.
- **CLI exit code contract** (`exit(1)` on critical/high, `exit(0)` on clean) is the right design for CI/CD pipeline integration.
- **`--no-report` flag** preserves terminal-only use case without writing files.
- **`discoverFiles` single-file shortcut** (lines 26–28) allows scanning individual files without glob overhead.
- **`demo/server.js` dynamic route loading** via `import(pathToFileURL(...))` is a clean pattern that gracefully falls back to 501 stubs for missing routes.
- **`src/utils/ast-helpers.js`** is the most well-tested utility file — 13 tests covering all 6 exported functions with positive, negative, and null-guard cases.

---

### Test Coverage Assessment (Member 1)

| Test File | Count | Missing Scenarios |
|---|---|---|
| `ast-parser.test.js` | 8 tests | No test for TypeScript syntax (`.ts` extension is not in discover scope anyway, but decorators etc could trip the parser) |
| `file-discovery.test.js` | 7 tests | No test for non-existent path (M1-7); no test for symlink handling |
| `scanner.test.js` | 7 tests | No test for scan of a single file path; no test for missing `rulesDir` with bad path |
| `rule-registry.test.js` | 5 tests | No test for invalid `severity` value (M1-5); no test for rule with valid `id`/`analyze` but wrong `category` |
| `cli.test.js` | ❌ 0 tests | Entire file untested — `resolveReportTarget`, exit code logic, `--no-report` flag |
| `types/finding.test.js` | ❌ 0 tests | `createFinding()` factory never tested |

---

### Member 1 Implementation Plan

| Priority | Task | File |
|---|---|---|
| P1 | Add `tests/cli.test.js` — test `resolveReportTarget`, exit codes, and `--no-report` flag | `tests/cli.test.js` (new) |
| P1 | Remove the fallback `generateMarkdownReport` in `cli.js` or make the import failure a hard error | `src/cli.js` |
| P2 | Add `severity` + `category` contract validation to `rule-registry.js` | `src/engine/rule-registry.js` |
| P2 | Add non-existent path guard in `file-discovery.js` | `src/engine/file-discovery.js` |
| P2 | Pre-hash seed passwords in `demo/db/setup.js` with MD5 to match the vulnerable auth flow | `demo/db/setup.js` |
| P3 | Import version from `package.json` instead of hardcoding `'1.0.0'` in scanner + CLI | `src/engine/scanner.js`, `src/cli.js` |
| P3 | Either delete `createFinding()` or wire it into `scanner.js`'s finding normalization | `src/types/finding.js`, `src/engine/scanner.js` |
| P3 | Add a `tests/types/finding.test.js` for the `createFinding` factory | `tests/types/finding.test.js` (new) |

---

## Final Overall Health (All 5 Members)

```
Member 1 (Team Lead / Engine):  🟡 Solid foundation — CLI untested, duplicate fallback code, minor robustness gaps
Member 2 (Secrets/Crypto):      🟡 Functional but has correctness gap (unused patterns, missing prefix checks)
Member 3 (Injection):           🔴 Rule body works but high FP risk + ESM import inconsistency — needs attention
Member 4 (Auth/Payment):        🟢 Best quality in rules codebase — minor DRY and edge case fixes only
Member 5 (Reporting/Demo):      🟡 Strong foundation — reporter coupling, demo auth logic bug, brittle E2E count
```

### Global Priority Fix Order (Demo Day Readiness)

| # | Fix | Owner | Impact |
|---|---|---|---|
| 1 | **M3-2** Fix ESM `traverse` import in `sql-injection.js` + `missing-input-validation.js` | Member 3 | Runtime risk |
| 2 | **M5-3** Fix salt-inconsistency in `demo-fixed/routes/auth.js` login | Member 5 | Demo breaks |
| 3 | **M1-1** Add `tests/cli.test.js` with exit-code and `resolveReportTarget` tests | Member 1 | Coverage gap |
| 4 | **M2-1** Wire `SECRET_PATTERNS` from `patterns.js` into `hardcoded-secrets.js` | Member 2 | Detection gap |
| 5 | **M5-1** Decouple reporter from AI enhancer (remove internal chain correlation call) | Member 5 | Architecture |
| 6 | **M1-2** Remove duplicate `generateMarkdownReport` fallback from `cli.js` | Member 1 | Code duplication |
| 7 | **M3-1** Import `DB_SINKS`/`DB_OBJECTS` from `patterns.js` in sql-injection rule | Member 3 | Inconsistency |
| 8 | **M5-2** Replace `sk_test_placeholder_key_123` fallback strings before demo | Member 5 | FP risk |
| 9 | **M1-5** Add severity/category validation to `rule-registry.js` | Member 1 | Robustness |
| 10 | **M5-8** Relax `toHaveLength(8)` to `toBeGreaterThanOrEqual(8)` | Member 5 | Test brittleness |
