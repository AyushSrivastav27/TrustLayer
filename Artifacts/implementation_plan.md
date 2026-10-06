# TrustLayer — Critical Hackathon Brainstorm & Implementation Plan

> **Author**: Senior AppSec / DevSecOps Engineer — Hackathon Mentor Review
> **Status**: DRAFT — Awaiting your approval before execution
> **Context**: 5-person team, 24–48 hours, Node.js/TypeScript ecosystem, cybersecurity domain

---

## Table of Contents
1. [Problem Fit](#1-problem-fit)
2. [Competitor / Existing Tool Analysis](#2-competitor--existing-tool-analysis)
3. [Product Type Comparison](#3-product-type-comparison)
4. [The Real MVP](#4-the-real-mvp)
5. [Security Check Evaluation](#5-security-check-evaluation)
6. [Authorization Deep-Dive](#6-authorization-deep-dive)
7. [Payment Security](#7-payment-security)
8. [AI Architecture](#8-ai-architecture)
9. [Demo Application](#9-demo-application)
10. [Team Task Breakdown](#10-team-task-breakdown)
11. [Git / PR Workflow](#11-git--pr-workflow)
12. [Architecture](#12-architecture)
13. [Technology Choices](#13-technology-choices)
14. [Demo Flow](#14-demo-flow)
15. [Differentiation](#15-differentiation)
16. [Feasibility Timeline](#16-feasibility-timeline)
17. [Failure Analysis](#17-failure-analysis)
18. [Final Project Proposal](#18-final-project-proposal)

---

## 1. Problem Fit

### Mapping: Problem Statement → TrustLayer

| Problem Statement Requirement | TrustLayer Feature | How Demonstrated | Fit |
|---|---|---|---|
| Hardcoded API secrets | Regex + entropy secret detection | Scan demo app, find `.env` values in source | ✅ STRONG |
| Unauthenticated database endpoints | Pattern: routes without auth middleware | AST checks for middleware chains | ⚠️ PARTIAL |
| Missing authorization checks between users | Pattern: req.params.id used without ownership check | Narrowed IDOR pattern detection | ⚠️ PARTIAL |
| Client-side payment values tampered in transit | Source→sink: `req.body.amount` → payment API | Data-flow trace in demo app | ✅ STRONG |
| Static scanner | Core CLI scanner | `trustlayer scan ./project` | ✅ STRONG |
| Pre-commit review tool | Git hook integration | Pre-commit hook demo | ✅ STRONG |
| Hardened reference application | Fixed version of demo app | Before/after scan comparison | ✅ STRONG |
| Defensive pattern demonstrating mitigation | Each finding includes remediation | Report shows fix + rescan | ✅ STRONG |
| Continuous request validation | NOT a runtime tool | — | ❌ MISS |
| Strict RBAC | Static pattern detection only | Limited to code pattern checks | ⚠️ PARTIAL |
| Least-privilege DB permissions | Config/code pattern check | Look for `SELECT *`, root credentials | ⚠️ PARTIAL |
| Secure payment callbacks / webhook signatures | Pattern: webhook handler without signature verification | AST check on webhook routes | ✅ STRONG |
| Credential stuffing / fake registrations | Runtime attack — not static | — | ❌ MISS |
| Coupon exploitation | Business logic — not statically detectable | — | ❌ MISS |
| Anomaly detection in application logs | Runtime analysis — not static | — | ❌ MISS |
| Injection (SQL, command, XSS) | AST source→sink analysis | Demo app with injectable endpoints | ✅ STRONG |

### Honest Assessment

> [!IMPORTANT]
> **TrustLayer covers ~60% of the problem statement well.** The remaining 40% (runtime anomaly detection, credential stuffing, coupon exploitation, continuous request validation) are fundamentally runtime/dynamic concerns that a static scanner cannot address. **Do NOT try to fake coverage of these.**

**Recommendation**: Acknowledge the gap in your demo. Say: *"These are runtime concerns. Our tool focuses on the pre-deployment phase where these vulnerabilities are introduced."* Judges respect intellectual honesty more than fake feature coverage.

---

## 2. Competitor / Existing Tool Analysis

### MEDUSA (Pantheon-Security)

**What it claims**: "AI-first security scanner" with "40,000+ detection patterns" and "74+ specialized scanners."

**What it actually is** (research-validated): A **deterministic, rule-based regex/pattern matching engine** written in Python. Despite the "AI-first" label:

- **ZERO AI/ML runtime dependencies.** Its `pyproject.toml` lists only `click`, `rich`, `tqdm`, `requests`, `pyyaml`, `psutil`, `defusedxml`. No OpenAI SDK, no Anthropic SDK, no PyTorch, no transformers.
- **NO native AST parsing.** The core engine does not parse code into ASTs.
- **NO data-flow or taint analysis.** It operates strictly on "positive-pattern attack-shapes" (surface syntax matching).
- **Wraps external linters.** For deep language analysis, it calls Bandit (Python) and ESLint (JS) via subprocess — if installed.
- The "40,000 patterns" are cartesian-multiplied regex permutations of keyword lists, not 40,000 semantic rules.
- The "AI-first" label refers to its **target domain** (AI/LLM application security — prompt injection, MCP configs, RAG poisoning) and the fact that Claude was used as a development co-author.

**Maturity**: ~1,000 stars, ~155 forks, 347 commits, 4 contributors (including `@claude` as credited author). Founded Nov 2025. Open-core with paywalled runtime rules behind `licensing.py`.

**Its real innovation**: Not static analysis computer science — rather **domain curation** of AI-ecosystem-specific rules (`.claude/hooks/` vetting, `.cursorrules` scanning, MCP server config validation).

**What it does NOT do that we CAN**:
- ❌ No AST-based analysis → we use Babel AST
- ❌ No source-to-sink data flow → we trace `req.body.amount` → payment API
- ❌ No e-commerce/payment security rules → our core differentiator
- ❌ No Express middleware chain analysis → we check auth middleware presence
- ❌ 583 false-positive suppression rules needed → our narrow scope = lower FP rate

> [!TIP]
> **MEDUSA's biggest weakness is exactly our strength.** It cannot trace whether untrusted data actually reaches a dangerous sink. It flags `pickle.load()` whenever it sees the string — it can't tell if the argument came from a trusted file or a network payload. Our AST + scope-aware analysis is genuinely more sophisticated for our narrow domain.

### VulnHawk

**What it claims**: "AI-powered SAST scanner that revolutionizes detection of complex logic bugs, authentication bypasses, and IDORs that Semgrep and CodeQL miss."

**What it actually is** (research-validated): A **prompt-enrichment pipeline for LLMs.** It discovers source files, slices code into chunks using regex/heuristic patterns for route definitions, enriches chunks with sibling endpoint context, and sends everything to an LLM (Claude, OpenAI, or Ollama) to spot anomalies.

**The detection mechanism for IDOR/auth bypass**:
- It feeds the LLM 10-20 sibling endpoints alongside the target endpoint
- If 19 endpoints enforce tenant checks and the 20th doesn't, the LLM flags the discrepancy
- **This is literally "send code to LLM with extra context."** No CFG, no DFG, no symbol table, no formal taint analysis.

**Maturity**: ~85 stars, 18 forks, single-maintainer project from GreyCore Labs (pentest firm). v0.2.x releases. Very early stage.

**What's technically interesting** (credit where due):
- The "enrichment" pattern of providing sibling endpoints as baseline context for consistency checking is genuinely clever
- SARIF pre-filtering integration (use Semgrep as high-recall pre-filter, LLM for high-precision validation) is architecturally sound

**Critical weaknesses**:
- **Non-deterministic**: Multiple runs on identical code yield different findings and severity ratings
- **Hallucination risk**: LLM may report fictitious line numbers or invented vulnerabilities
- **No AST or data-flow**: Zero program representation — all "analysis" is whatever the LLM infers from reading text
- **Expensive at scale**: Every chunk sent to GPT-4o/Claude = API cost
- **Context window fragility**: Complex logic across service classes gets severed from context

> [!CAUTION]
> **VulnHawk validates our architectural decision.** Its approach proves that pure LLM-based vulnerability detection is unreliable and non-reproducible. Our hybrid approach — deterministic AST detection FIRST, AI for explanation SECOND — is fundamentally more trustworthy. We should explicitly state this in our demo.

### Comparison with Established Tools

| Tool | What It Does Well | Your Overlap | Your Disadvantage |
|---|---|---|---|
| **Semgrep** | Pattern matching on ASTs, custom rules, taint analysis | Your entire rule engine concept | Semgrep has 3000+ community rules, professional team, years of development |
| **Gitleaks** | Secret detection via regex + entropy | Your secret scanning | Gitleaks has 800+ regex patterns, battle-tested |
| **ESLint security plugins** | JS/TS security linting | Your JS security checks | Already integrated into every Node.js project |
| **CodeQL** | Deep data-flow analysis, semantic queries | Your source→sink analysis | CodeQL has a full compiler-grade analysis engine |
| **Snyk** | Dependency scanning, SAST, container scanning | Your dependency checks | Snyk is a $8B company |
| **SonarQube** | Comprehensive code quality + security | Your overall concept | 30+ years of development |

### What This Means for You

**If you build a generic scanner, you are building a worse version of every tool above.**

The only defensible strategy: **pick a narrow vertical that none of these tools do well and go deep.**

---

## 3. Product Type Comparison

| Type | Technical Value | Demo Value | Difficulty | Differentiation | 48hr Feasibility |
|---|---|---|---|---|---|
| **A. CLI static scanner** | Medium — generic pattern matching | Medium — terminal output isn't exciting | Medium | LOW — every security tool is a CLI scanner | ✅ Feasible |
| **B. VS Code extension** | Medium — inline annotations | HIGH — visual, interactive | HIGH — VS Code API learning curve | Medium | ⚠️ Risky |
| **C. Pre-commit tool** | Medium — gate on commit | LOW — boring to demo | LOW | LOW — husky + lint exists | ✅ Feasible |
| **D. GitHub PR reviewer** | HIGH — fits developer workflow | HIGH — PR annotations are visual | HIGH — GitHub API, webhook server | Medium | ❌ Too complex |
| **E. Vuln app + scanner** | HIGH — shows attack + defense | HIGHEST — attack narrative | Medium | Medium — depends on scanner quality | ✅ Feasible |
| **F. Hardened reference app** | LOW — just "here's good code" | LOW — no drama | LOW | LOW | ✅ Feasible |
| **G. Scanner + AI reviewer** | Medium — depends on AI integration | Medium — AI output can be fluffy | Medium-HIGH | LOW — everyone is doing this | ✅ Feasible |
| **H. E-commerce security audit pipeline** | HIGH — domain-specific | HIGH — real-world story | Medium | HIGH — nobody focuses on this | ✅ Feasible |

### My Recommendation: **Option E + H hybrid**

> [!TIP]
> **Build a domain-specific security scanner focused on e-commerce/payment application security, demonstrated against a deliberately vulnerable e-commerce app.**

**Why this wins**:
1. **Narrow focus** = deeper checks = more impressive than broad+shallow
2. **E-commerce/payment focus** directly matches the problem statement's emphasis on payment security
3. **Nobody in the established tool ecosystem specializes in e-commerce payment security patterns**
4. **The demo tells a story**: "Here's a startup that shipped an e-commerce app fast. Here's how an attacker exploits the payment flow. Here's how our tool catches it before deployment."

---

## 4. The Real MVP

### MUST HAVE (Core — Demo will fail without these)

1. **Hardcoded secret detection** — regex + high-entropy string detection
2. **Client-controlled payment amount** — source→sink: `req.body.amount` → payment API call
3. **Missing webhook signature verification** — webhook route without `crypto.timingSafeEqual` or equivalent
4. **Missing authentication middleware** — Express routes without auth middleware in chain
5. **SQL injection** — string concatenation/template literal with user input in SQL queries
6. **Deliberately vulnerable demo app** — Express.js e-commerce app with all above vulnerabilities
7. **SECURITY-REPORT.md generation** — structured findings with file, line, severity, explanation, fix
8. **CLI interface** — `trustlayer scan ./project`

### SHOULD HAVE (Improves demo, not critical path)

9. **IDOR pattern** — `req.params.id` used in DB query without ownership check
10. **Missing rate limiting** — login/payment routes without rate-limit middleware
11. **AI-enhanced explanations** — for each finding, generate exploitation scenario + remediation
12. **Before/after comparison** — scan fixed app, show finding resolution

### NICE TO HAVE (Only if time permits)

13. **XSS detection** — user input rendered without sanitization
14. **Insecure cookie configuration** — missing `httpOnly`, `secure`, `sameSite` flags
15. **Debug mode detection** — `DEBUG=true`, `NODE_ENV !== 'production'`
16. **Pre-commit hook** — run scanner on `git commit`

### DO NOT BUILD

- ❌ VS Code extension (too much time on UI, not enough on detection)
- ❌ GitHub PR integration (requires webhook server, OAuth, complex setup)
- ❌ Dependency vulnerability scanning (just use `npm audit` — no value in rebuilding this)
- ❌ CORS misconfiguration detection (too many false positives, context-dependent)
- ❌ Full data-flow / taint analysis engine (you're not building CodeQL in 48 hours)
- ❌ Credential stuffing detection (runtime concern)
- ❌ Anomaly detection (runtime concern)
- ❌ Multi-language support (focus on JavaScript/TypeScript only)
- ❌ Container/infrastructure scanning
- ❌ Path traversal detection (complex, overlaps with other tools)
- ❌ Command injection (rare in Node.js e-commerce apps)

---

## 5. Security Check Evaluation

| Check | Static Detectability | Reliability | Complexity | FP Risk | FN Risk | AST Useful? | Data-flow Useful? | AI Useful? | **BUILD?** |
|---|---|---|---|---|---|---|---|---|---|
| Hardcoded secrets | HIGH — regex + entropy | HIGH | LOW | MEDIUM (test keys) | LOW | No — regex sufficient | No | For explanation | ✅ YES |
| SQL injection | HIGH — string concat in query | HIGH | MEDIUM | LOW | MEDIUM | YES — template literals | YES — user input → query | For remediation | ✅ YES |
| XSS | MEDIUM — depends on framework | MEDIUM | HIGH | HIGH (frameworks auto-escape) | HIGH | YES | YES | Medium | ⚠️ MAYBE |
| Command injection | HIGH — exec/spawn with user input | HIGH | MEDIUM | LOW | MEDIUM | YES | YES | Medium | ❌ NO — rare in e-commerce |
| Path traversal | MEDIUM | MEDIUM | MEDIUM | MEDIUM | HIGH | YES | YES | Medium | ❌ NO — niche |
| Input validation | LOW — what counts as "validated"? | LOW | HIGH | VERY HIGH | VERY HIGH | No | No | Medium | ❌ NO — too vague |
| Authentication (missing middleware) | MEDIUM — pattern matching | MEDIUM | MEDIUM | MEDIUM (not all routes need auth) | MEDIUM | YES — middleware chain | No | YES — context | ✅ YES |
| Authorization / RBAC | LOW — highly context-dependent | LOW | VERY HIGH | VERY HIGH | VERY HIGH | Minimal | Minimal | MEDIUM | ⚠️ NARROW ONLY |
| IDOR/BOLA | MEDIUM — narrow pattern | MEDIUM | MEDIUM | MEDIUM | HIGH | YES | YES | YES | ✅ YES (narrow) |
| JWT issues | MEDIUM — config patterns | HIGH | LOW | LOW | MEDIUM | No — string matching | No | For explanation | ⚠️ MAYBE |
| Payment amount tampering | HIGH — very specific pattern | HIGH | LOW | LOW | LOW (in target apps) | YES | YES | For exploitation story | ✅ YES — DIFFERENTIATOR |
| Webhook sig verification | HIGH — absence of crypto check | HIGH | LOW | LOW | LOW (in target apps) | YES — function body analysis | No | For explanation | ✅ YES — DIFFERENTIATOR |
| Payment callback validation | MEDIUM | MEDIUM | MEDIUM | MEDIUM | MEDIUM | YES | Partial | YES | ✅ YES |
| Rate limiting | MEDIUM — absence of middleware | HIGH | LOW | MEDIUM | MEDIUM | YES — middleware check | No | For context | ✅ YES |
| DB privilege | LOW — requires infra context | LOW | HIGH | HIGH | HIGH | No | No | No | ❌ NO |
| Dependency vulns | HIGH (use npm audit) | HIGH | LOW | LOW | LOW | No | No | No | ❌ NO — use existing tools |
| CORS | MEDIUM | LOW | MEDIUM | VERY HIGH | HIGH | No — config check | No | Medium | ❌ NO |
| Insecure cookies | HIGH — config pattern | HIGH | LOW | LOW | MEDIUM | No | No | For explanation | ⚠️ MAYBE |
| Debug mode | HIGH — env check | HIGH | LOW | MEDIUM | MEDIUM | No | No | No | ⚠️ MAYBE |
| HTTPS | LOW — deployment concern | LOW | N/A | HIGH | HIGH | No | No | No | ❌ NO |
| Weak password hashing | HIGH — function name check | HIGH | LOW | LOW | MEDIUM | No | No | For explanation | ⚠️ MAYBE |

### Summary: Build These 8 Checks

1. ✅ Hardcoded secrets (regex + entropy)
2. ✅ SQL injection (AST — string concat in DB calls)
3. ✅ Missing authentication middleware (Express middleware chain)
4. ✅ IDOR pattern (`req.params.id` → DB query without ownership)
5. ✅ Client-controlled payment amount (source→sink)
6. ✅ Missing webhook signature verification
7. ✅ Missing rate limiting on sensitive routes
8. ✅ Insecure payment callback handling

---

## 6. Authorization Deep-Dive

### What Can Static Analysis Actually Detect?

Let me be brutally honest here:

**Full authorization verification is impossible for static analysis.** Authorization is a semantic property of the application — it depends on business logic, user roles, data ownership, and context that no static scanner can fully understand.

Here's the hierarchy from "detectable" to "impossible":

| Level | What | Detectable? | How |
|---|---|---|---|
| **Authentication present** | Is there auth middleware on a route? | ✅ YES | Check Express middleware chain for `isAuthenticated`, `verifyToken`, passport patterns |
| **Role check present** | After auth, is there a role/permission check? | ⚠️ PARTIALLY | Look for `req.user.role`, `checkPermission()`, `authorize('admin')` patterns |
| **Role check correct** | Is the role check using the RIGHT role? | ❌ NO | Cannot know business intent |
| **Ownership check present** | Does the handler verify `resource.userId === req.user.id`? | ⚠️ PARTIALLY | Pattern: `req.params.id` used in query, no comparison with `req.user.id` |
| **Ownership check correct** | Is the ownership check actually correct? | ❌ NO | Cannot verify business logic |
| **RBAC enforcement complete** | Are ALL routes properly protected? | ❌ NO | Cannot know which routes should be protected |

### Technically Defensible Checks We CAN Implement

**Check 1: Missing Authentication Middleware**
```
Pattern: app.get('/api/resource/:id', (req, res) => { ... })
vs
Pattern: app.get('/api/resource/:id', isAuthenticated, (req, res) => { ... })

Detection: Route handler without middleware that matches known auth patterns
Reliability: MEDIUM — will flag public routes as FP
Mitigation: Allow `// trustlayer-ignore: public-route` comments
```

**Check 2: IDOR Pattern (Narrow)**
```
Pattern:
  1. Route parameter: req.params.id or req.params.userId
  2. Used in database query: db.query('SELECT * FROM orders WHERE id = ?', [req.params.id])
  3. No comparison: req.user.id === resource.userId is absent

Detection: AST analysis of route handler body
Reliability: MEDIUM — narrow pattern, useful for demo
Limitation: Only catches the exact pattern, misses abstracted access
```

**Check 3: Direct Object Reference Without Scoping**
```
Pattern:
  db.findById(req.params.id) without WHERE user_id = req.user.id

This is a specific sub-pattern of IDOR. Detectable in demo-style code.
```

> [!CAUTION]
> **Never claim your scanner "detects authorization vulnerabilities." Instead say: "Our scanner identifies common patterns that indicate missing ownership verification in data access, which is a precondition for IDOR/BOLA attacks."**

---

## 7. Payment Security

### This Is Your Differentiator

> [!TIP]
> **The problem statement specifically emphasizes payment security. Semgrep, ESLint-security, Gitleaks — none of them have payment-security-specific rules. This is your gap.**

### Detectable Payment Patterns

**Pattern 1: Client-Controlled Transaction Amount** ✅ HIGH CONFIDENCE
```javascript
// VULNERABLE
app.post('/checkout', (req, res) => {
  const amount = req.body.amount;  // ← SOURCE: user-controlled
  stripe.charges.create({
    amount: amount,               // ← SINK: payment API
    currency: 'usd',
    source: req.body.token,
  });
});

// Detection: AST analysis
// Source: req.body.amount, req.body.price, req.query.amount
// Sink: stripe.charges.create, razorpay.orders.create, paymentIntent.create
// Rule: Source flows to sink without server-side price lookup
```

**Pattern 2: Missing Webhook Signature Verification** ✅ HIGH CONFIDENCE
```javascript
// VULNERABLE
app.post('/webhook/stripe', (req, res) => {
  const event = req.body;           // ← Trusting raw body
  processPayment(event);
});

// SECURE
app.post('/webhook/stripe', (req, res) => {
  const sig = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(req.rawBody, sig, secret);
  processPayment(event);
});

// Detection: Route matching /webhook|callback|notify/ pattern
// Check: Handler body contains crypto verification or SDK verification function
// Absence = finding
```

**Pattern 3: Missing Idempotency / Duplicate Payment Check** ⚠️ MEDIUM CONFIDENCE
```javascript
// VULNERABLE
app.post('/webhook/payment', (req, res) => {
  updateOrderStatus(req.body.orderId, 'paid');
  // No check if already processed
});

// Detection: Webhook handler that modifies state without checking existing state
// More complex — better as AI-augmented check
```

**Pattern 4: Insecure Payment Callback URL** ⚠️ MEDIUM CONFIDENCE
```javascript
// VULNERABLE
const order = razorpay.orders.create({
  amount: amount,
  callback_url: 'http://example.com/payment/success',  // HTTP, not HTTPS
});

// Detection: String matching on callback_url with http:// prefix
```

**Pattern 5: Client-Side Payment Verification** ✅ HIGH CONFIDENCE
```javascript
// VULNERABLE — trusting frontend for payment status
app.post('/order/complete', (req, res) => {
  if (req.body.paymentStatus === 'success') {  // ← Client says "I paid"
    fulfillOrder(req.body.orderId);
  }
});

// Detection: req.body.paymentStatus or similar used to gate order fulfillment
// Without server-side payment verification API call
```

### Why This Works as a Differentiator

1. **No existing tool has specialized payment security rules** for JavaScript
2. **Directly addresses the problem statement** — payment security is called out specifically
3. **Narrow enough to be reliable** — we're checking specific API patterns, not general logic
4. **Demo-friendly** — "here's how an attacker changes the price from $100 to $1" is visceral
5. **Technically defensible** — these are real source→sink patterns, not AI hand-waving

---

## 8. AI Architecture

### What NOT to Do

```
❌ Entire codebase → LLM → "Tell me all vulnerabilities"

Problems:
- Context window limits
- LLM hallucination = false findings
- Non-deterministic results
- Slow
- Expensive
- Not reproducible
- No different from "paste code in ChatGPT"
```

### Defensible AI Architecture

```
PHASE 1: Static Detection (deterministic, fast, reproducible)
    │
    ├── Regex engine → secret candidates
    ├── AST analysis → injection patterns
    ├── Middleware analysis → auth gaps
    └── Source→sink analysis → payment flow issues
    │
    ▼
FINDINGS (structured: file, line, rule, code snippet, severity)
    │
    ▼
PHASE 2: AI Enhancement (non-critical, additive)
    │
    ├── For EACH finding individually:
    │   ├── Extract 30-50 lines of surrounding code context
    │   ├── Send: finding + context + rule metadata
    │   ├── Ask AI to:
    │   │   ├── Confirm or downgrade severity (FP reduction)
    │   │   ├── Explain exploitation scenario
    │   │   ├── Generate specific remediation code
    │   │   └── Rate confidence (high/medium/low)
    │   └── Merge AI response into finding
    │
    └── Cross-finding correlation:
        ├── Send all findings summary
        ├── Ask AI to identify attack chains
        └── Example: "secret exposure + missing auth + SQL injection = full database compromise"
    │
    ▼
ENRICHED REPORT
```

### Is This Actually Useful?

**YES, but only if AI is additive, not foundational.**

| AI Role | Usefulness | Risk | Recommendation |
|---|---|---|---|
| **Reduce false positives** | HIGH — AI can recognize test keys vs real keys | Medium — may miss real secrets | ✅ YES |
| **Explain findings** | HIGH — generates human-readable exploitation scenarios | LOW | ✅ YES |
| **Generate remediation code** | HIGH — practical value for developers | Medium — may generate insecure code | ✅ YES with review caveat |
| **Identify architectural weaknesses** | LOW-MEDIUM — too vague without full context | HIGH — hallucination | ⚠️ OPTIONAL |
| **Correlate multiple findings** | MEDIUM — attack chain identification | Medium | ✅ YES — great for demo |
| **Review auth/authz logic** | LOW — AI can't reliably understand business intent | VERY HIGH | ❌ NO as primary detector |

### Key Principle

> [!IMPORTANT]
> **The scanner must produce useful results even if the LLM API is down.** AI enhances the report; it does not create it. If you remove the AI layer, you should still have a working security scanner with actionable findings.

### Graceful Degradation
```
if (llmAvailable) {
  finding.explanation = await ai.explain(finding);
  finding.remediation = await ai.generateFix(finding);
  finding.confidence = await ai.assessConfidence(finding);
} else {
  finding.explanation = rules[finding.ruleId].defaultExplanation;
  finding.remediation = rules[finding.ruleId].defaultFix;
  finding.confidence = rules[finding.ruleId].defaultConfidence;
}
```

---

## 9. Demo Application

### Vulnerable E-Commerce App: "QuickShop"

A deliberately vulnerable Node.js/Express e-commerce API with 8 intentional vulnerabilities, each mapping directly to the problem statement.

#### Architecture
```
demo/
├── server.js          ← Main Express app
├── routes/
│   ├── auth.js        ← Login/register (vuln: hardcoded secret, weak hash)
│   ├── products.js    ← Product listing (vuln: SQL injection)
│   ├── orders.js      ← Order management (vuln: IDOR, no auth on some routes)
│   ├── checkout.js    ← Payment processing (vuln: client-controlled amount)
│   └── webhook.js     ← Payment webhook (vuln: no signature verification)
├── middleware/
│   └── auth.js        ← Authentication middleware
├── db/
│   └── setup.js       ← SQLite setup with seed data
├── .env.example       ← Template
└── package.json
```

#### The 8 Vulnerabilities

| # | Vulnerability | File | Line Pattern | Problem Statement Mapping | Detection Method |
|---|---|---|---|---|---|
| 1 | **Hardcoded JWT secret** | `routes/auth.js` | `const JWT_SECRET = 'supersecret123'` | "hardcoded API secrets" | Regex + entropy |
| 2 | **SQL injection** | `routes/products.js` | `` `SELECT * FROM products WHERE name LIKE '%${req.query.search}%'` `` | "injection" | AST — template literal with user input in SQL |
| 3 | **Missing auth on order route** | `routes/orders.js` | `router.get('/orders/:id', (req, res) => {...})` — no auth middleware | "unauthenticated database endpoints" | Middleware chain analysis |
| 4 | **IDOR — view any user's orders** | `routes/orders.js` | `db.get('SELECT * FROM orders WHERE id = ?', [req.params.id])` — no user scoping | "missing authorization checks between users" | AST — req.params → DB query without user scoping |
| 5 | **Client-controlled payment amount** | `routes/checkout.js` | `amount: req.body.amount` passed to payment API | "client-side payment values that can be tampered" | Source→sink: req.body → payment API |
| 6 | **Missing webhook signature verification** | `routes/webhook.js` | `const event = req.body; processPayment(event);` | "secure payment callbacks, webhook signatures" | Absence of crypto verification in webhook handler |
| 7 | **No rate limiting on login** | `routes/auth.js` | `router.post('/login', ...)` without rate-limit middleware | "credential stuffing" | Middleware absence check on auth routes |
| 8 | **Weak password hashing** | `routes/auth.js` | `const hash = md5(password)` | "security oversights" | Function name check: md5, sha1, sha256 without salt |

#### Fixed Version

Each vulnerability has a corresponding fix, stored in a parallel `demo-fixed/` directory or applied via patches. The demo shows:

1. Scan vulnerable app → 8 findings
2. Apply fixes
3. Rescan → 0 findings

---

## 10. Team Task Breakdown

### Member 1 — YOU (Team Lead / Core Integrator)

**Responsibilities**:
- Core scanner engine (`src/engine/`)
- CLI interface (`src/cli.ts`)
- File discovery and AST parsing pipeline
- Rule interface definition (`src/types/rule.ts`)
- Integration of all rule modules
- PR review and merge
- Demo app skeleton
- Final testing and demo

**Files you own**:
```
src/cli.ts
src/engine/scanner.ts
src/engine/file-discovery.ts
src/engine/ast-parser.ts
src/types/rule.ts
src/types/finding.ts
src/types/report.ts
demo/server.js
demo/package.json
demo/db/setup.js
```

**Critical deliverable**: The rule interface that all members must implement:
```typescript
// src/types/rule.ts
export interface Rule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  defaultExplanation: string;
  defaultRemediation: string;
  
  // The detection function
  analyze(context: AnalysisContext): Finding[];
}

export interface AnalysisContext {
  filePath: string;
  fileContent: string;
  ast: AST | null;          // Parsed AST (for .js/.ts files)
  lines: string[];          // File content split by lines
}

export interface Finding {
  ruleId: string;
  severity: string;
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  codeSnippet: string;      // The problematic code
  message: string;          // What's wrong
  explanation?: string;     // Why it's dangerous (AI-enhanced)
  remediation?: string;     // How to fix (AI-enhanced)
  confidence: 'high' | 'medium' | 'low';
}
```

**You create this interface FIRST (hour 1-2). Everything else depends on it.**

---

### Member 2 — Secrets & Configuration Rules

**Branch**: `feature/secrets-config`

**Deliverable**: Two rule modules:
1. `src/rules/hardcoded-secrets.ts` — Detect hardcoded API keys, passwords, tokens
2. `src/rules/weak-crypto.ts` — Detect weak hashing (md5, sha1 without salt)

**Files they own**:
```
src/rules/hardcoded-secrets.ts
src/rules/weak-crypto.ts
tests/rules/hardcoded-secrets.test.ts
tests/rules/weak-crypto.test.ts
```

**Interface they implement**: `Rule` interface from `src/types/rule.ts`

**Detection approach for secrets**:
```typescript
// Regex patterns for common secrets
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'Generic API Key', regex: /['"]?(api[_-]?key|apikey|api[_-]?secret)['"]?\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/ },
  { name: 'JWT Secret', regex: /['"]?(jwt[_-]?secret|token[_-]?secret|secret[_-]?key)['"]?\s*[:=]\s*['"][^'"]{8,}['"]/ },
  { name: 'Database URL', regex: /(mongodb|postgres|mysql):\/\/[^'"\s]+/ },
  { name: 'Private Key', regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
  { name: 'Generic Password', regex: /['"]?(password|passwd|pwd)['"]?\s*[:=]\s*['"][^'"]{4,}['"]/ },
];
// + Shannon entropy check for high-entropy strings assigned to suspicious variable names
```

**Test cases**:
- File with hardcoded `JWT_SECRET = 'abc123'` → finding
- File with `process.env.JWT_SECRET` → no finding
- File with `const testKey = 'test-key-123'` → finding (but lower confidence)
- File with `md5(password)` → finding for weak crypto
- File with `bcrypt.hash(password, 10)` → no finding

**PR Requirements**:
- Both rule files implementing the `Rule` interface
- All test cases passing
- No modifications to files outside `src/rules/` and `tests/rules/`

**Dependencies**: Rule interface from Member 1 (available by hour 2)

---

### Member 3 — Injection & Input Rules

**Branch**: `feature/injection`

**Deliverable**: Two rule modules:
1. `src/rules/sql-injection.ts` — Detect SQL injection via string concatenation/template literals
2. `src/rules/missing-input-validation.ts` — Detect `eval()`, `Function()`, `child_process.exec()` with user input

**Files they own**:
```
src/rules/sql-injection.ts
src/rules/missing-input-validation.ts
tests/rules/sql-injection.test.ts
tests/rules/missing-input-validation.test.ts
```

**Detection approach for SQL injection**:
```typescript
// AST-based detection:
// 1. Find template literals or string concatenation
// 2. Check if they contain SQL keywords (SELECT, INSERT, UPDATE, DELETE, WHERE)
// 3. Check if they interpolate user input (req.body, req.query, req.params)
// 4. Flag as SQL injection

// Example AST walk:
// TemplateLiteral
//   ├── quasis: ["SELECT * FROM users WHERE name = '", "'"]
//   └── expressions: [MemberExpression: req.query.name]
//   → SQL keyword present + user input interpolated = FINDING
```

**Test cases**:
- Template literal with `req.query` in SQL string → finding
- Parameterized query `db.query('SELECT * FROM users WHERE id = ?', [id])` → no finding
- String concat `"SELECT * FROM users WHERE name = '" + name + "'"` → finding
- ORM call `User.findById(id)` → no finding

**PR Requirements**:
- Both rule files implementing the `Rule` interface
- All test cases passing
- No modifications outside `src/rules/` and `tests/rules/`

**Dependencies**: Rule interface + AST parser utilities from Member 1 (available by hour 2-3)

---

### Member 4 — Payment Security & Auth Rules

**Branch**: `feature/payment-auth`

**Deliverable**: Three rule modules:
1. `src/rules/payment-amount-tampering.ts` — Detect client-controlled payment amounts
2. `src/rules/missing-webhook-verification.ts` — Detect webhook handlers without signature checks
3. `src/rules/missing-auth-middleware.ts` — Detect routes without authentication middleware

**Files they own**:
```
src/rules/payment-amount-tampering.ts
src/rules/missing-webhook-verification.ts
src/rules/missing-auth-middleware.ts
tests/rules/payment-amount-tampering.test.ts
tests/rules/missing-webhook-verification.test.ts
tests/rules/missing-auth-middleware.test.ts
```

**Detection approach for payment amount tampering**:
```typescript
// Source: req.body.amount, req.body.price, req.body.total
// Sink: stripe.charges.create, razorpay.orders.create, paypal.payment.create
// Rule: If source flows to sink argument without an intermediate
//       database/server lookup (e.g., Product.findById → product.price),
//       flag as client-controlled amount

// Simplified for hackathon:
// 1. Find function calls matching payment API patterns
// 2. Check if amount argument traces back to req.body/req.query
// 3. If yes → FINDING
```

**Detection approach for webhook verification**:
```typescript
// Pattern: Route handler matching /webhook|callback|ipn|notify/
// Check handler body for:
//   - stripe.webhooks.constructEvent
//   - crypto.createHmac / crypto.timingSafeEqual
//   - razorpay.validateWebhookSignature
//   - any signature/HMAC verification function
// Absence = FINDING
```

**Test cases**:
- Checkout route passing `req.body.amount` to Stripe → finding
- Checkout route using `product.price` from DB → no finding
- Webhook route without signature check → finding
- Webhook route with `constructEvent()` → no finding
- API route without auth middleware → finding
- API route with `isAuthenticated` middleware → no finding
- Public route (`/`, `/products`, `/health`) → no finding (whitelist)

**PR Requirements**:
- All three rule files implementing the `Rule` interface
- All test cases passing
- No modifications outside `src/rules/` and `tests/rules/`

**Dependencies**: Rule interface + AST utilities from Member 1

---

### Member 5 — Report Generator & AI Integration + Demo Vulnerabilities

**Branch**: `feature/reporting-ai`

**Deliverable**:
1. `src/reporters/markdown-reporter.ts` — Generate SECURITY-REPORT.md from findings
2. `src/reporters/json-reporter.ts` — Generate JSON report
3. `src/ai/enhancer.ts` — AI enhancement of findings (explanation, remediation, attack chains)
4. Demo app vulnerable route files

**Files they own**:
```
src/reporters/markdown-reporter.ts
src/reporters/json-reporter.ts
src/ai/enhancer.ts
tests/reporters/markdown-reporter.test.ts
demo/routes/auth.js
demo/routes/products.js
demo/routes/orders.js
demo/routes/checkout.js
demo/routes/webhook.js
demo-fixed/  (entire directory)
```

**Report format**:
```markdown
# 🔒 TrustLayer Security Report

**Project**: ./demo
**Scan Date**: 2026-09-30T10:00:00Z
**Total Findings**: 8
**Critical**: 3 | **High**: 3 | **Medium**: 2 | **Low**: 0

---

## CRITICAL: Hardcoded JWT Secret

**File**: `routes/auth.js:5`
**Rule**: `secrets/hardcoded-secret`
**Confidence**: High

### Vulnerable Code
\`\`\`javascript
const JWT_SECRET = 'supersecret123';
\`\`\`

### Why This Is Dangerous
[AI-generated or default explanation]

### How to Exploit
[AI-generated exploitation scenario]

### Recommended Fix
\`\`\`javascript
const JWT_SECRET = process.env.JWT_SECRET;
\`\`\`

---
[... more findings ...]

## Attack Chain Analysis
[AI-generated: "Combining finding #1 (exposed secret) with finding #3 (missing auth),
an attacker could forge JWT tokens and access any user's orders..."]
```

**AI enhancer interface**:
```typescript
// src/ai/enhancer.ts
export interface AIEnhancer {
  enhanceFinding(finding: Finding, codeContext: string): Promise<EnhancedFinding>;
  generateAttackChains(findings: Finding[]): Promise<AttackChain[]>;
}

export interface EnhancedFinding extends Finding {
  aiExplanation: string;
  aiExploitScenario: string;
  aiRemediation: string;
  aiConfidence: 'high' | 'medium' | 'low';
}

export interface AttackChain {
  name: string;
  findings: string[];  // finding IDs involved
  narrative: string;   // AI-generated attack story
  severity: string;
}
```

**PR Requirements**:
- Reporter generates valid markdown from Finding[]
- AI enhancer works with and without API key (graceful degradation)
- Demo app files contain all 8 planned vulnerabilities
- Demo-fixed directory contains fixed versions
- No modifications outside owned files

**Dependencies**: Finding type definition from Member 1

---

### Task Assignment Summary

| Member | Branch | Primary Deliverable | Files Owned | Depends On |
|---|---|---|---|---|
| **1 (You)** | `main` | Core engine, CLI, interfaces, integration | `src/engine/`, `src/cli.ts`, `src/types/` | Nobody |
| **2** | `feature/secrets-config` | Secrets + weak crypto rules | `src/rules/hardcoded-secrets.ts`, `src/rules/weak-crypto.ts` | Rule interface (hr 2) |
| **3** | `feature/injection` | SQL injection + unsafe eval rules | `src/rules/sql-injection.ts`, `src/rules/missing-input-validation.ts` | Rule interface + AST utils (hr 3) |
| **4** | `feature/payment-auth` | Payment security + auth middleware rules | `src/rules/payment-*.ts`, `src/rules/missing-auth-middleware.ts` | Rule interface + AST utils (hr 3) |
| **5** | `feature/reporting-ai` | Reports + AI + demo app routes | `src/reporters/`, `src/ai/`, `demo/routes/` | Finding type (hr 2), All rules (hr 18 for AI enhancement) |

---

## 11. Git / PR Workflow

### Branch Strategy

```
main (protected — only you merge)
│
├── feature/secrets-config     (Member 2)
├── feature/injection          (Member 3)
├── feature/payment-auth       (Member 4)
└── feature/reporting-ai       (Member 5)
```

### Merge Order (Critical!)

```
1. You push: core engine + interfaces + CLI skeleton    → main
2. Members 2,3,4 branch from main after interfaces land
3. Member 5 branches from main after interfaces land
4. Merge order:
   a. feature/secrets-config   (no dependencies on other rules)
   b. feature/injection        (no dependencies on other rules)
   c. feature/payment-auth     (no dependencies on other rules)
   d. feature/reporting-ai     (after all rules merged — reporter needs to handle them)
```

### Why This Won't Have Merge Conflicts

1. **Each member owns different files** — no shared file editing
2. **Rule modules are self-contained** — each is a separate file that exports a `Rule` implementation
3. **The engine auto-discovers rules** — you use dynamic import or a registry pattern:

```typescript
// src/engine/rule-registry.ts (YOU OWN THIS)
import { Rule } from '../types/rule';

// Auto-discover all rule files
export async function loadRules(): Promise<Rule[]> {
  const ruleFiles = glob.sync('./src/rules/*.ts');
  const rules: Rule[] = [];
  for (const file of ruleFiles) {
    const module = await import(file);
    if (module.default && typeof module.default.analyze === 'function') {
      rules.push(module.default);
    }
  }
  return rules;
}
```

This means: **when a member adds a new rule file to `src/rules/`, it's automatically discovered. No need to edit a central registry file.**

### PR Requirements Template

```markdown
## PR Checklist
- [ ] Implements Rule interface from src/types/rule.ts
- [ ] Only modifies files in my assigned directories
- [ ] All tests pass: `npm test -- --grep "rule-name"`
- [ ] No hardcoded file paths
- [ ] No modifications to src/engine/ or src/cli.ts
- [ ] Exported as default export
- [ ] Includes at least 3 test cases (true positive, true negative, edge case)
```

---

## 12. Architecture

### Recommended Repository Structure

```
trustlayer/
├── src/
│   ├── cli.ts                          ← YOU: CLI entry point
│   ├── types/
│   │   ├── rule.ts                     ← YOU: Rule interface
│   │   ├── finding.ts                  ← YOU: Finding type
│   │   └── report.ts                   ← YOU: Report type
│   ├── engine/
│   │   ├── scanner.ts                  ← YOU: Orchestrator
│   │   ├── file-discovery.ts           ← YOU: Find files to scan
│   │   ├── ast-parser.ts              ← YOU: Parse JS/TS to AST
│   │   └── rule-registry.ts           ← YOU: Auto-load rules
│   ├── rules/                          ← MEMBERS: One file per rule
│   │   ├── hardcoded-secrets.ts        ← Member 2
│   │   ├── weak-crypto.ts             ← Member 2
│   │   ├── sql-injection.ts           ← Member 3
│   │   ├── missing-input-validation.ts ← Member 3
│   │   ├── payment-amount-tampering.ts ← Member 4
│   │   ├── missing-webhook-verification.ts ← Member 4
│   │   └── missing-auth-middleware.ts  ← Member 4
│   ├── reporters/                      ← Member 5
│   │   ├── markdown-reporter.ts
│   │   └── json-reporter.ts
│   ├── ai/                             ← Member 5
│   │   └── enhancer.ts
│   └── utils/                          ← YOU: Shared utilities
│       ├── ast-helpers.ts              ← AST traversal helpers
│       └── patterns.ts                 ← Shared regex patterns
├── demo/                               ← Vulnerable app
│   ├── server.js                       ← YOU: Main app skeleton
│   ├── routes/                         ← Member 5
│   │   ├── auth.js
│   │   ├── products.js
│   │   ├── orders.js
│   │   ├── checkout.js
│   │   └── webhook.js
│   ├── middleware/
│   │   └── auth.js
│   ├── db/
│   │   └── setup.js                    ← YOU: SQLite setup
│   └── package.json
├── demo-fixed/                         ← Member 5: Fixed versions
├── tests/
│   ├── rules/                          ← Each member writes their own tests
│   │   ├── hardcoded-secrets.test.ts
│   │   ├── sql-injection.test.ts
│   │   └── ...
│   ├── engine/                         ← YOU
│   │   └── scanner.test.ts
│   └── fixtures/                       ← Shared test fixtures
│       ├── vulnerable-sample.js
│       └── safe-sample.js
├── docs/
│   └── RULES.md                        ← Auto-generated rule documentation
├── tsconfig.json
├── package.json
├── .gitignore
└── README.md
```

### Key Architectural Decisions

1. **Rule auto-discovery via filesystem** — no central import file that everyone edits
2. **Each rule is a single file** — complete isolation
3. **AST parsing is centralized** — you provide parsed AST to rules, rules don't parse
4. **Reporter takes `Finding[]`** — decoupled from rules
5. **AI enhancer is optional** — scanner works without it

---

## 13. Technology Choices

| Technology | Use For | Recommendation | Rationale |
|---|---|---|---|
| **Node.js** | Runtime | ✅ USE | Your team's strength |
| **TypeScript** | Language | ✅ USE | Type safety for interfaces, better tooling |
| **@babel/parser** | JS/TS AST parsing | ✅ USE | Native JS parser, familiar ecosystem, handles JSX/TS, well-documented AST format |
| **@babel/traverse** | AST walking | ✅ USE | Pairs with babel/parser, visitor pattern |
| **Tree-sitter** | AST parsing | ❌ SKIP | More powerful but steep learning curve, C bindings can break, overkill for single-language |
| **Semgrep** | Pattern matching | ❌ SKIP | External dependency, Python-based, would make you "a Semgrep wrapper" |
| **CodeQL** | Data-flow analysis | ❌ SKIP | Requires database build step, Java-based, way too complex |
| **ESLint** | Linting framework | ❌ SKIP | Building on ESLint makes you "an ESLint plugin," not a standalone tool |
| **Commander.js** | CLI framework | ✅ USE | Simple, well-known, minimal learning curve |
| **chalk** | CLI colors | ✅ USE | Colored terminal output for demo impact |
| **glob** | File discovery | ✅ USE | Find files matching patterns |
| **OpenAI/Anthropic SDK** | AI enhancement | ✅ USE (optional) | API for LLM integration |
| **better-sqlite3** | Demo app database | ✅ USE | For the vulnerable demo app, zero-config |
| **Express** | Demo app framework | ✅ USE | Most common Node.js framework |
| **Vitest** | Testing | ✅ USE | Fast, TypeScript-native, modern |
| **Git hooks (husky)** | Pre-commit | ⚠️ OPTIONAL | Nice-to-have, not core |
| **VS Code API** | Extension | ❌ SKIP | Too much time for too little value |

### Parser Decision: Why Babel, Not Tree-sitter

Babel is the right choice because:
1. Pure JavaScript — no native compilation issues
2. Your team already knows the JS AST format from ESLint
3. `@babel/traverse` provides a clean visitor API
4. Handles TypeScript, JSX, flow out of the box
5. `@babel/parser` produces an ESTree-compatible AST
6. Well-documented: every node type is documented at astexplorer.net

Tree-sitter would be better for multi-language support, but you're targeting JS/TS only.

---

## 14. Hackathon Demo Flow

### The Story: "QuickShop — Shipped Fast, Left Open"

**Time: 3–5 minutes**

---

**ACT 1: The Problem (45 seconds)**

> *"Meet QuickShop — a startup e-commerce API built by a team that moved fast. They launched in a weekend. Customers are buying products, making payments. Everything works.*
>
> *But they left the doors wide open."*

Show: QuickShop running. Make a normal API call — create account, browse products, place an order. Everything looks fine.

---

**ACT 2: The Attack (60 seconds)**

> *"Let me show you what an attacker sees."*

**Live demo exploitation** (using curl or Postman):

1. **Payment tampering**: `curl -X POST /checkout -d '{"productId": 1, "amount": 1}'` — bought a $500 item for $0.01
2. **IDOR**: `curl /orders/1` — can see another user's order without authentication
3. **SQL injection**: `curl /products?search=' OR 1=1--` — dumped all products

> *"Three API calls. Stolen goods, data exposure, database compromise. This is what 'Shipped Fast, Left Open' looks like."*

---

**ACT 3: TrustLayer Scan (60 seconds)**

> *"Now let's run TrustLayer before this ever reaches production."*

```bash
$ trustlayer scan ./quickshop

🔍 TrustLayer Security Scanner v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning 12 files...

🔴 CRITICAL  Hardcoded JWT Secret           routes/auth.js:5
🔴 CRITICAL  SQL Injection                  routes/products.js:14
🔴 CRITICAL  Client-Controlled Payment      routes/checkout.js:8
🟠 HIGH      Missing Auth Middleware         routes/orders.js:11
🟠 HIGH      IDOR - No Ownership Check      routes/orders.js:15
🟠 HIGH      Missing Webhook Verification   routes/webhook.js:4
🟡 MEDIUM    No Rate Limiting on Login      routes/auth.js:22
🟡 MEDIUM    Weak Password Hashing (MD5)    routes/auth.js:18

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Found 8 security issues (3 critical, 3 high, 2 medium)

📄 Full report: SECURITY-REPORT.md
```

---

**ACT 4: The Report (45 seconds)**

Open `SECURITY-REPORT.md`. Show ONE finding in detail:

> *"Let's look at the payment vulnerability. TrustLayer traced the data flow: `req.body.amount` on line 8 flows directly into `stripe.charges.create` on line 12. No server-side price verification. The AI explains: an attacker can intercept the checkout request and set any price. Here's the recommended fix — look up the price from the database instead."*

Show the attack chain analysis:

> *"TrustLayer also correlates findings. It identified that the hardcoded JWT secret combined with the missing auth middleware creates a full authentication bypass — an attacker can forge tokens and access any endpoint."*

---

**ACT 5: The Fix (45 seconds)**

> *"Let's apply the fixes and rescan."*

```bash
$ trustlayer scan ./quickshop-fixed

🔍 TrustLayer Security Scanner v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning 12 files...

✅ No security issues found.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your codebase passed all security checks.
```

> *"Zero findings. Every vulnerability has been remediated. That's TrustLayer — catching 'Shipped Fast, Left Open' before it reaches production."*

---

**ACT 6: What Makes This Different (30 seconds)**

> *"Unlike generic SAST tools, TrustLayer specializes in e-commerce security patterns that tools like Semgrep don't check for — client-controlled payment amounts, missing webhook signature verification, payment callback validation. These are domain-specific vulnerabilities that cause real financial damage, and they're invisible to general-purpose scanners."*

---

## 15. Differentiation

### When Judges Ask: "Why Not Just Use Semgrep?"

**Answer 1: Payment-Security-Specific Detection Rules**

> "Semgrep has 3,000+ rules. Zero of them detect client-controlled payment amounts flowing into Stripe/Razorpay API calls. Zero check for missing webhook signature verification. Zero validate payment callback integrity. We built domain-specific rules for e-commerce payment security — a gap that exists in every major SAST tool."

This is verifiable. You can run `semgrep --config=auto` on your demo app and show it does NOT flag the payment vulnerabilities.

**Answer 2: Attack Chain Correlation**

> "Semgrep finds individual issues. We correlate findings into attack chains. A hardcoded secret alone is medium severity. A hardcoded secret + missing auth middleware + IDOR = full account takeover. Our tool identifies these compound attack paths and explains the escalation."

This is the AI component doing genuinely useful work — not just explaining individual findings, but showing how they combine.

**Answer 3: Problem-Statement-Native Design**

> "We didn't build a generic scanner. We built a tool specifically for the 'Shipped Fast, Left Open' problem — rapid-deployment e-commerce apps with payment flows. Every check maps to a real vulnerability pattern from the problem statement. We demonstrate detection AND exploitation AND remediation for each finding."

### When Judges Ask: "Why Not MEDUSA/VulnHawk?"

> "MEDUSA and VulnHawk are general-purpose AI scanners. They send code to an LLM and ask 'is this vulnerable?' Our tool uses deterministic, reproducible static analysis first. AI only enhances findings that were already detected. If you turn off the AI, you still get reliable detection. If you turn off MEDUSA's AI, you get regex."

> "Also — neither tool has e-commerce payment security rules. Neither detects client-controlled transaction amounts or missing webhook signatures. We went deep on a specific domain instead of wide on general scanning."

---

## 16. Feasibility Timeline

### Phase 1: Foundation (Hours 0–6)

**YOU (Member 1)**:
- [ ] Initialize repo, TypeScript config, package.json
- [ ] Define all interfaces (`Rule`, `Finding`, `AnalysisContext`, `Report`)
- [ ] Build file discovery module
- [ ] Build AST parser wrapper (Babel)
- [ ] Build rule registry (auto-discovery)
- [ ] Build basic scanner orchestrator
- [ ] Build CLI skeleton (`trustlayer scan <path>`)
- [ ] Push to `main`
- [ ] Notify team: "Interfaces are ready, branch and go"

**All Other Members**:
- [ ] Set up development environment
- [ ] Study the Rule interface
- [ ] Create their feature branches
- [ ] Begin implementing their assigned rules (stubs)
- [ ] Member 5: Start building demo app skeleton

**At end of Phase 1**: CLI runs, discovers files, parses ASTs, loads rules (even if no rules exist yet). Members have branches and are actively coding.

### Phase 2: Core Rules (Hours 6–12)

**YOU**:
- [ ] Build AST helper utilities (node traversal, pattern matching)
- [ ] Build demo app skeleton (`server.js`, `db/setup.js`)
- [ ] Start reviewing early PRs
- [ ] Test rule integration as PRs come in

**Member 2**: Complete `hardcoded-secrets.ts` + `weak-crypto.ts` + tests → PR

**Member 3**: Complete `sql-injection.ts` + `missing-input-validation.ts` + tests → PR

**Member 4**: Complete `payment-amount-tampering.ts` + `missing-webhook-verification.ts` + `missing-auth-middleware.ts` + tests → PR

**Member 5**: Complete demo app route files with all 8 vulnerabilities + start on reporters

**At end of Phase 2**: At least 2 rule PRs merged. Scanner produces real findings on demo app. Demo app runs and is exploitable.

### Phase 3: Integration & AI (Hours 12–18)

**YOU**:
- [ ] Merge remaining rule PRs
- [ ] Fix integration issues
- [ ] End-to-end test: scan demo app → findings
- [ ] Help Member 5 with AI integration if needed

**Member 5**:
- [ ] Complete markdown reporter → PR
- [ ] Complete AI enhancer → PR
- [ ] Complete demo-fixed/ directory

**Other Members** (if their rules are merged):
- [ ] Write additional test fixtures
- [ ] Help with demo app polish
- [ ] Write demo-fixed/ versions of their vulnerability areas
- [ ] Work on nice-to-have rules

**At end of Phase 3**: Full pipeline works: scan → findings → AI enhancement → report. Demo app has both vulnerable and fixed versions.

### Phase 4: Polish & Demo Prep (Hours 18–24)

**YOU**:
- [ ] Full end-to-end testing
- [ ] Fix edge cases and bugs
- [ ] Polish CLI output (colors, formatting, progress bar)
- [ ] Write README.md
- [ ] Practice demo flow

**Member 5**: Polish report formatting, test AI fallback

**All Members**: Practice demo, prepare for Q&A, document architecture

**At end of Phase 4**: Demo-ready. Can run the full 5-minute demo without technical failures.

### Phase 5: Buffer (Hours 24–48, if available)

- [ ] Add nice-to-have rules (XSS, cookie security)
- [ ] Add pre-commit hook integration
- [ ] Run scanner on a real open-source project (not just your demo)
- [ ] Prepare slide deck if needed
- [ ] Sleep

---

## 17. Failure Analysis

### What Could Fail During Demo

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **LLM API is down/slow** | MEDIUM | HIGH if AI is core | Graceful degradation: pre-cached AI responses for demo findings |
| **AST parser crashes on edge case** | MEDIUM | HIGH | Try-catch around parser, skip unparseable files |
| **Scanner produces zero findings** | LOW | CRITICAL | Pre-test the exact demo app before presenting |
| **Scanner produces false positives on fixed app** | MEDIUM | HIGH | Thoroughly test the fixed version |
| **Demo app won't start** | LOW | HIGH | Test on a fresh machine/env |
| **npm install fails** | LOW | MEDIUM | Commit `package-lock.json`, have offline cache |
| **Live coding/curl fails** | MEDIUM | MEDIUM | Pre-record the attack demo as backup |

### False Positive Risks

| Check | False Positive Scenario | Mitigation |
|---|---|---|
| **Hardcoded secrets** | Test keys, example values, constants that look like keys | Entropy threshold, allow `test`, `example`, `placeholder` |
| **Missing auth middleware** | Public routes that shouldn't have auth | Whitelist: `/`, `/health`, `/products`, `/docs` |
| **Missing rate limiting** | Routes that don't need rate limiting | Only flag auth + payment routes |
| **SQL injection** | ORMs that handle parameterization internally | Only flag raw `db.query`, `db.run`, `db.exec` with string interpolation |

### Impossible-to-Reliably Detect (Be Honest)

- ❌ **Business logic vulnerabilities** — "is the coupon discount capped?" requires business context
- ❌ **Complete RBAC correctness** — "does admin role check cover all admin actions?" requires intent
- ❌ **Cryptographic misuse beyond obvious** — "is this AES mode appropriate?" is context-dependent
- ❌ **Race conditions** — timing issues are runtime, not static
- ❌ **Full data-flow across files** — inter-file taint tracking requires a sophisticated engine you won't build

### Overambitious Features to Remove

- ❌ Path traversal detection — too edge-case for e-commerce focus
- ❌ Command injection — rare in e-commerce apps
- ❌ CORS misconfiguration — too many false positives
- ❌ HTTPS detection — deployment concern, not code concern
- ❌ Database privilege detection — requires infrastructure context
- ❌ Full dependency scanning — `npm audit` exists, don't rebuild

### Where AI Makes Things Worse

1. **Non-deterministic output** — same code, different scan results = looks broken
2. **Hallucinated vulnerability** — AI "finds" something that isn't there = undermines credibility
3. **Slow scans** — LLM API calls add 2-10 seconds per finding = bad UX
4. **False confidence** — "AI says it's high severity" with no technical basis

**Mitigation**: AI is NEVER the detector. AI only enhances human-readable output for findings already detected by deterministic rules. Cache AI responses for demo.

### What Would Make Judges See This As a Wrapper

- "We run Semgrep rules and add ChatGPT explanations" → WRAPPER
- "We run npm audit and make it pretty" → WRAPPER
- "We use ESLint security plugin with a custom reporter" → WRAPPER

### What Would Make It Technically Impressive

- Custom AST-based payment amount flow detection → ORIGINAL
- Attack chain correlation (finding A + finding B = exploit C) → ORIGINAL
- Domain-specific e-commerce security rules → ORIGINAL
- Live exploitation demo matching scanner findings → COMPELLING
- Before/after scan showing remediation → PRACTICAL

---

## 18. Final Project Proposal

```
PROJECT NAME:     TrustLayer
ONE-LINE PITCH:   E-commerce security scanner that catches payment vulnerabilities,
                  auth gaps, and injection flaws before they ship to production.

PROBLEM:          Startups ship e-commerce apps fast, leaving payment flows 
                  exploitable, API endpoints unauthenticated, and secrets 
                  hardcoded. Generic SAST tools miss domain-specific e-commerce 
                  patterns like client-controlled payment amounts and 
                  missing webhook signature verification.

TARGET USER:      Node.js/Express developers building e-commerce or payment
                  applications who need pre-deployment security checks.

CORE VALUE:       Domain-specific static analysis for e-commerce security patterns
                  that no existing SAST tool covers, with AI-enhanced reporting
                  that explains exploitation scenarios and generates fixes.

ARCHITECTURE:
    CLI command → File Discovery → AST Parsing (Babel) 
    → Rule Engine (auto-discovered rule modules) → Findings 
    → AI Enhancement (optional) → Report Generation (Markdown/JSON)

MUST-HAVE FEATURES:
    1. Hardcoded secret detection (regex + entropy)
    2. SQL injection detection (AST — template literal + DB call)
    3. Client-controlled payment amount detection (source→sink)
    4. Missing webhook signature verification
    5. Missing authentication middleware on routes
    6. IDOR pattern detection (req.params → DB without user scope)
    7. Missing rate limiting on auth/payment routes
    8. Weak password hashing detection
    9. Structured SECURITY-REPORT.md generation
    10. CLI: trustlayer scan <path>

DEMO APPLICATION:
    "QuickShop" — deliberately vulnerable Express.js e-commerce API
    with 8 intentional vulnerabilities matching the problem statement.
    Includes vulnerable + fixed versions for before/after demo.

AI ROLE:
    Enhancement layer only. Deterministic rules detect; AI explains.
    - Generates exploitation scenarios for each finding
    - Generates remediation code suggestions
    - Correlates findings into attack chains
    - Graceful degradation if LLM unavailable

TEAM STRUCTURE:
    Member 1 (YOU): Core engine, CLI, interfaces, integration, PR review
    Member 2: Secret detection + weak crypto rules
    Member 3: SQL injection + unsafe eval rules
    Member 4: Payment security + auth middleware rules (DIFFERENTIATOR)
    Member 5: Reporter + AI enhancer + demo app vulnerabilities

TECH STACK:
    - TypeScript + Node.js
    - @babel/parser + @babel/traverse (AST)
    - Commander.js (CLI)
    - chalk (colored output)
    - Vitest (testing)
    - Express + better-sqlite3 (demo app)
    - OpenAI/Anthropic SDK (AI enhancement)

DEMO FLOW:
    1. Show QuickShop running normally
    2. Live-exploit: payment tamper, IDOR, SQL injection (60s)
    3. Run TrustLayer scan → 8 findings (60s)
    4. Show report detail: source→sink, attack chain (45s)
    5. Apply fixes, rescan → 0 findings (45s)
    6. Explain differentiation: payment-specific rules (30s)

DIFFERENTIATION:
    1. E-commerce payment security rules (no SAST tool has these)
    2. Attack chain correlation (findings → compound exploits)
    3. Deterministic detection + AI explanation (not "AI-first")

WHAT WE WILL NOT BUILD:
    - VS Code extension
    - Multi-language support
    - Dependency scanning (use npm audit)
    - Full taint analysis engine
    - Runtime anomaly detection
    - Credential stuffing detection
    - Container/infrastructure scanning
    - GitHub PR integration

24–48 HOUR PLAN:
    Hours 0–6:   Core engine + interfaces + CLI skeleton + team branches
    Hours 6–12:  All rules implemented + demo app built + first PRs merged
    Hours 12–18: Integration + AI enhancement + reporter + end-to-end testing
    Hours 18–24: Polish + demo prep + practice + edge case fixes
    Hours 24–48: Nice-to-haves + additional testing + sleep
```

> [!IMPORTANT]
> **The single most important decision**: Focus on e-commerce/payment security as your differentiator. Don't try to be "Semgrep but in TypeScript." Be "the tool that catches the payment vulnerability Semgrep misses."

---

## Open Questions for Your Review

1. **AI Provider**: Which LLM API does your team have access to? OpenAI, Anthropic, Google, or a local model? This affects the AI enhancement architecture.

2. **Demo App Complexity**: Should QuickShop be a full REST API (8-10 endpoints) or a minimal API (4-5 endpoints)? More endpoints = more realistic but more work for Member 5.

3. **Payment Provider**: Should the demo use Stripe patterns, Razorpay patterns, or generic payment API patterns? This affects which SDK function names the rules look for.

4. **Team Member Skill Levels**: Are all 4 members comfortable with TypeScript and Babel AST? If not, Member 2 (regex-only rules) might be the right assignment for less experienced members.

5. **Pre-commit Hook**: Is this worth including in the demo? It adds differentiation (developer workflow integration) but requires extra setup time.

6. **Real-world Validation**: Should we also demo the scanner on a real open-source Node.js e-commerce project (like a OWASP Juice Shop clone)? This proves the tool works beyond our controlled demo app.
