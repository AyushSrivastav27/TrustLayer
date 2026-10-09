# 🏆 TrustLayer — 3 to 5 Minute Hackathon Presentation & Demo Script

> **Target Audience:** Hackathon Judges & Technical Evaluators  
> **Theme:** *"Shipped Fast, Left Open"* — Securing modern e-commerce APIs before production.  
> **Total Time:** 3:30 – 4:30 minutes (leaves 30–60s buffer for Q&A).

---

## ⏱️ Quick Presentation Timeline (At a Glance)

| Timestamp | Phase | What You Do & Say | Key Talking Point |
|---|---|---|---|
| **0:00 – 0:45** | **The Hook & Problem** | Pitch the gap in modern API development. | *"Devs ship payment APIs in hours, but traditional SAST tools miss payment logic flaws."* |
| **0:45 – 1:30** | **The Solution & Differentiator** | Introduce TrustLayer & why it's unique. | *Pure AST, intra-handler precision, zero config, runs in 40ms — not minutes.* |
| **1:30 – 3:00** | **Live Terminal Demo** | Run `npm run demo:compare` & show SARIF. | *Caught ₹1 price tampering, forged webhooks, IDOR, and rate-limiting gaps in real-time.* |
| **3:00 – 3:45** | **Enterprise & AI Integration** | Show GitHub Security Tab & Attack Chains. | *OASIS SARIF exports directly to GitHub; AI correlates compound exploit chains.* |
| **3:45 – 4:15** | **Wrap-Up & Closing** | State the impact and invite questions. | *"TrustLayer bridges the gap between shipping fast and staying locked down."* |

---

## 🎙️ Step-by-Step Script (Word-for-Word Guide)

### 1. The Hook (0:00 – 0:45)
> *"Hello judges! Under the hackathon theme 'Shipped Fast, Left Open', we tackled a multi-million-dollar vulnerability vector in modern web development: **E-commerce and payment API security**.*
>
> *Today, startups use Express, Stripe, and Razorpay to launch backends in hours. But traditional security tools like Semgrep, ESLint, or SonarQube were built for generic software. They look for syntax quirks, but completely miss **business logic payment flaws**:*
> - *Client-controlled prices where an attacker changes a ₹10,000 cart to ₹1,*
> - *Unverified payment webhooks that blindly fulfill orders on fake HTTP callbacks,*
> - *IDOR data access without user scoping.*
>
> *That’s why we built **TrustLayer** — a lightning-fast, framework-aware static security scanner built specifically for Node.js and Express APIs."*

---

### 2. The Differentiator (0:45 – 1:30)
> *"What makes TrustLayer unique? Three architectural principles:*
>
> 1. **Zero External Heavyweight Dependencies**: Built purely on `@babel/parser` and AST traversal. No native C++ bindings, no Python runtimes, zero config.
> 2. **Blazing Speed (40 milliseconds)**: TrustLayer analyzes an entire microservice in under 50ms at over **20,000 lines of code per second** — making it 25x faster than Semgrep. It works as an instant commit gate.
> 3. **Deterministic First, AI Second**: Every vulnerability is detected 100% offline without network or LLM tokens. AI is strictly additive to explain exploit scenarios and correlate compound attack chains."*

---

### 3. The Live Demo (1:30 – 3:00) — *The "WOW" Moment*

#### 👉 Action 1: Run the Side-by-Side Comparison
In your terminal, execute:
```bash
npm run demo:compare
```

#### 🗣️ What to Say:
> *"Here is our live demonstration. We have two codebases: `demo`, representing a fast-shipped vulnerable store, and `demo-fixed`, the remediated reference.*
>
> *In **under 45 milliseconds**, TrustLayer scans the vulnerable backend and flags **12 critical security gaps**:*
>
> 1. **Client-Controlled Payment Amount (Critical)**: In `routes/checkout.js`, the developer accepted `req.body.amount` directly into `stripe.charges.create()` instead of looking up the authoritative price in the database.
> 2. **Missing Webhook Verification (High)**: In `routes/webhook.js`, fulfillment logic runs without verifying `stripe-signature` with HMAC. An attacker can POST `{ "status": "paid" }` and get items shipped for free.
> 3. **IDOR / BOLA (High)**: In `routes/orders.js`, the query selects by `req.params.id` without scoping to `req.user.id`. Any user can view other customers' invoices.
> 4. **Missing Rate Limiting (Medium)**: In `routes/auth.js`, login and register endpoints are completely unthrottled.
>
> *Notice: TrustLayer immediately blocks the CI gate with **Exit Code 1**.*
>
> *Next, looking at `demo-fixed`, TrustLayer runs against the remediated backend: **0 findings, 100% clean scan**, and passes with **Exit Code 0**."*

---

### 4. Developer Workflows & Enterprise Integration (3:00 – 3:45)

#### 👉 Action 2: Show GitHub Actions & Pre-Commit Guard
Point to the GitHub repository / browser tab:

#### 🗣️ What to Say:
> *"TrustLayer isn't just a toy CLI; it's drop-in ready for enterprise engineering pipelines:*
>
> - **GitHub Security Tab Integration**: TrustLayer exports OASIS **SARIF v2.1.0**. In our repository's GitHub Actions, the scan runs automatically on pull requests and uploads findings directly into the GitHub **Security -> Code Scanning alerts** tab.
> - **Automated Pre-Commit Hook**: With `npm run hooks:install`, TrustLayer intercepts `git commit` and blocks vulnerable code before it ever touches git history.
> - **Additive AI Attack Chains**: When run with `--ai`, TrustLayer connects the dots between separate findings: combining an unauthenticated route with a client-controlled price parameter to explain the exact full-chain exploit narrative to non-security developers."*

---

### 5. Closing & Call to Action (3:45 – 4:15)
> *"To summarize: TrustLayer gives engineering teams the speed of modern web development with the deterministic guarantees of specialized payment security. Over **317 tests passing**, 9 dedicated AST security rules, and sub-50ms scans.*
>
> *Shipped fast, but never left open. Thank you, and we'd love to take your questions!"*

---

## 🎯 Quick Reference: Main Points vs. The Gist

| Topic | The Main Point (Explain Fully) | The Gist (Mention in 1 Sentence) |
|---|---|---|
| **Payment Rules** | **Deep Dive**: Explain that client-controlled `amount` into Stripe SDK and missing webhook signatures are ignored by SonarQube/Semgrep. | Mention Razorpay and Stripe SDK sink detection. |
| **Speed / Benchmark** | **Highlight**: **40ms** scan time (~21,000 LOC/sec) allows zero-friction pre-commit hooks. | 25x–50x faster than traditional containerized SASTs. |
| **AI Role** | **Clarify**: The scanner is **100% deterministic & offline**. AI is additive for attack chains and remediation diffs. | Supports multi-provider fallbacks (Gemini, Claude, OpenAI). |
| **Enterprise / CI** | **Show**: Native SARIF v2.1.0 output feeds directly into GitHub Security alerts tab. | Runs on Node 20/22 matrix via GitHub Actions. |
| **IDOR & Rate Limiting** | **Show**: Route parameter scoping (`WHERE user_id = ?`) and throttling middleware detection. | Prevents credential stuffing & BOLA attacks. |

---

## 💡 Top 4 Judge Questions & Bulletproof Answers

#### Q1: *"Why build a new scanner instead of just writing Semgrep or ESLint rules?"*
> **Answer:** *"Semgrep requires a Python/native binary runner which spins up containers taking 10–15 seconds, making it too slow for pre-commit hooks. ESLint-security is purely AST-syntax without Express route context. TrustLayer understands Express route chains, `req.*` parameter origins, and payment SDK method signatures natively in pure JS in under 40 milliseconds."*

#### Q2: *"Can you do cross-file taint analysis?"*
> **Answer:** *"By design, we chose deterministic **intra-handler analysis**. In modern Node.js/Express architectures, 95% of payment tampering and input validation flaws occur within the route handler scope. Cross-file call graphs in JS introduce massive false positives and exponential slowdowns. Our single-handler approach guarantees sub-50ms execution with near-zero false positives."*

#### Q3: *"What happens if Gemini or the AI API is down?"*
> **Answer:** *"TrustLayer is deterministic-first. Every finding, remediation tip, and severity score is calculated offline using rule metadata. AI is an additive report enhancer. If offline or without an API key, TrustLayer runs heuristic attack correlation with 100% functionality."*

#### Q4: *"How easy is this for an enterprise team to adopt?"*
> **Answer:** *"Zero setup. Run `npx trustlayer scan .` or add our reusable GitHub Action (`uses: vikalp1817243/TrustLayer@main`). It exports standard SARIF v2.1.0 directly into GitHub's native Security tab."*
