# 🛡️ TrustLayer — Aggressive Codebase Audit & Feature Roadmap

> **Audit & Hardening Strategy:** Modular Deep-Dive into Code Quality, AST Rule Edge Cases, Scanner Self-Defense, Engine Performance, and Phase 2 Packaging.  
> **Target System:** `TrustLayer` (`v1.0.0`)  
> **Status:** Planning & Execution Protocol  
> **Date:** October 2026

---

## 📑 Table of Contents

1. [Executive Summary & Objectives](#1-executive-summary--objectives)
2. [Module 1: Dead Code, Unused Exports & Redundancy Audit](#module-1-dead-code-unused-exports--redundancy-audit)
3. [Module 2: AST Rule Precision, False Positive & Negative Audit](#module-2-ast-rule-precision-false-positive--negative-audit)
4. [Module 3: Scanner Self-Defense & Input Hygiene (ReDoS, Path Traversal, OOM)](#module-3-scanner-self-defense--input-hygiene)
5. [Module 4: CLI, Reporting & AI Resiliency Audit](#module-4-cli-reporting--ai-resiliency-audit)
6. [Module 5: Phase 2 — Programmatic Library API & Distribution Packaging](#module-5-phase-2--programmatic-library-api--distribution-packaging)
7. [Module 6: Benchmark Harness & Demo Presentation Alignment](#module-6-benchmark-harness--demo-presentation-alignment)
8. [Comprehensive Execution Prompts Catalog](#comprehensive-execution-prompts-catalog)

---

## 1. Executive Summary & Objectives

While TrustLayer has achieved **100% test pass rate across 225 unit/integration tests**, real-world scans on large external codebases (such as 131-file repositories) reveal key areas where the scanner must be aggressively stress-tested before production and demo submission:

1. **Rule Interaction Refinement:** Preventing double-flagging when a route is intentionally an unauthenticated payment webhook that requires HMAC signature checks instead of user JWTs.
2. **Self-Security & Defensive Coding:** Protecting the scanner itself from Malicious Target Codebases (e.g., Catastrophic Backtracking / ReDoS in regexes, path traversal, circular symbolic links, unbounded AST memory consumption).
3. **Codebase Hygiene:** Eliminating zombie functions, unused exports, duplicate AST helpers, and unhandled promise rejections.
4. **Phase 2 Completion:** Providing a frictionless programmatic API (`import { scan } from 'trustlayer'`) and distribution-ready packaging.

---

## Module 1: Dead Code, Unused Exports & Redundancy Audit

### 🎯 Objective
Identify and remove dead code, unused helper exports, duplicated AST traversal utilities, or shadowed constants across all source files.

### 🔍 Scope & Target Files
- `src/utils/ast-helpers.js` vs `src/utils/patterns.js`
- `src/types/rule.js`, `src/types/finding.js`, `src/types/report.js`
- `src/engine/scanner.js`, `src/engine/ast-parser.js`, `src/engine/rule-registry.js`
- `src/cli.js`

### 📋 Audit Checkpoints
- [x] **Unused Helper Functions:** Check if any functions exported from `src/utils/ast-helpers.js` are never called across any of the 7 rules or engine files.
- [x] **Redundant Pattern Constants:** Cross-examine `patterns.js` against individual rule definitions to ensure regexes or sink arrays aren't re-declared locally.
- [x] **Shadowed Variables & Imports:** Verify Babel types (`t.*`) are imported cleanly and not redundantly declared.
- [x] **Type Contract Adherence:** Ensure all fields defined in `src/types/finding.js` and `src/types/rule.js` match what the scanner actually consumes and emits.

---

## Module 2: AST Rule Precision, False Positive & Negative Audit

### 🎯 Objective
Harden rules against real-world Express variations, reduce false alarms (such as the webhook vs. auth collision identified in real scans), and capture sophisticated vulnerability bypasses.

### 🔍 Scope & Target Files
- `src/rules/missing-auth-middleware.js`
- `src/rules/missing-webhook-verification.js`
- `src/rules/payment-amount-tampering.js`
- `src/rules/sql-injection.js`
- `src/rules/weak-crypto.js`
- `src/rules/hardcoded-secrets.js`
- `src/rules/missing-input-validation.js`

### 📋 Audit Checkpoints
- [ ] **Webhook vs Auth Mutual Exclusivity (Critical Real-World Gap):**
  - *Observation:* On `/webhook` routes, both `missing-auth-middleware` and `missing-webhook-verification` currently fire simultaneously.
  - *Refinement:* Webhook endpoints *by design* do not expect user session/JWT authentication. If a route path contains `/webhook`, `missing-auth-middleware` should gracefully defer to `missing-webhook-verification` or lower its severity/confidence to avoid noisy duplicate alerts.
- [ ] **Entity ID Randomness Context:**
  - *Observation:* `Math.random()` in frontend UI components (e.g. `const id = '#HOT-T' + Math.floor(...)`) flagged as High Severity crypto weakness.
  - *Refinement:* Add heuristic context checking: is the identifier used in cryptographic/session/token context vs harmless UI element styling?
- [ ] **Deep Destructuring & Parameter Aliasing:**
  - Ensure `const { amount: price } = req.body` or `const { body: { amount } } = req` is tracked by payment tampering.
- [ ] **Modern SQL Sinks & Tagged Templates:**
  - Verify Prisma raw queries (`prisma.$queryRawUnsafe`), Knex raw (`knex.raw`), and Sequelize raw queries are accurately distinguished from parameterized tagged templates (`prisma.$queryRaw` with template tags).
- [ ] **TypeScript / JSX AST Compatibility:**
  - Verify Babel parser handles Type Annotations, Interfaces, Generics, and TSX/JSX syntax without syntax error bailout.

---

## Module 3: Scanner Self-Defense & Input Hygiene

### 🎯 Objective
Ensure TrustLayer cannot be crashed, exploited, or frozen by the codebases it scans (Defensive SAST Design).

### 🔍 Scope & Target Files
- `src/utils/patterns.js` (Regexes)
- `src/engine/file-discovery.js` (Glob & File I/O)
- `src/engine/ast-parser.js` (Parser configuration)
- `src/engine/scanner.js` (Memory and async concurrency)

### 📋 Audit Checkpoints
- [ ] **ReDoS (Regular Expression Denial of Service):**
  - Audit every regex in `src/utils/patterns.js` and `src/rules/hardcoded-secrets.js` for polynomial or exponential catastrophic backtracking on specially crafted string inputs.
- [ ] **Symlink Loops & Path Traversal:**
  - Verify `discoverFiles()` does not enter infinite recursion when encountering cyclic directory symlinks (`followSymbolicLinks: false`).
- [ ] **Babel Parser Resource Exhaustion:**
  - Verify behavior when encountering minified bundle files (e.g. single 15MB line `vendor.bundle.js`).
  - Introduce file size limits (e.g., skip files > 2MB by default with a warning to avoid Node.js V8 heap out-of-memory crashes).
- [ ] **Malformed File Recovery:**
  - Test parser behavior on binary files accidentally named `.js`, zero-byte files, and syntax-broken files. Confirm `errorRecovery: true` prevents unhandled crashes.

---

## Module 4: CLI, Reporting & AI Resiliency Audit

### 🎯 Objective
Audit CLI flag combinations, error reporting, report output hygiene, and AI degradation boundaries.

### 🔍 Scope & Target Files
- `src/cli.js`
- `src/reporters/markdown-reporter.js`
- `src/reporters/json-reporter.js`
- `src/ai/enhancer.js`

### 📋 Audit Checkpoints
- [x] **CLI Flag Usability & POSIX Compliance:**
  - Ensure clear error messaging when users pass malformed flags (e.g. `-ai` vs `--ai`).
  - Add shorthand `-a` for `--ai` to prevent user typos.
- [x] **Exit Code Contract Verification:**
  - `0`: Scan completed cleanly, or findings below `--fail-on` threshold.
  - `1`: Vulnerabilities found equal to or exceeding `--fail-on` threshold.
  - `2`: System, I/O, or user syntax error (missing target, invalid format, missing directory).
- [x] **SARIF v2.1.0 Validation:**
  - Verify exported `.sarif` files against official JSON Schema validator for OASIS SARIF v2.1.0.
  - Ensure GitHub Code Scanning rejects zero fields (repo-relative URIs, `%SRCROOT%` base, markdown remediation, tags).
- [x] **AI Graceful Degradation & Timeout Integrity:**
  - Simulate network partition, 429 Rate Limit, and 500 Server Error from Gemini/Claude/OpenAI API.
  - Confirm scan always outputs deterministic report within failover timeouts and never hangs.

---

## Module 5: Phase 2 — Programmatic Library API & Distribution Packaging

### 🎯 Objective
Turn TrustLayer from a standalone CLI script into an installable npm package with both CLI and programmatic ESM API interfaces.

### 🔍 Scope & Target Files
- `src/index.js` (New Entrypoint)
- `package.json`
- `tests/engine/index.test.js` (New Test Suite)

### 📋 Action Items
- [x] **Create `src/index.js` Programmatic API:**
  - Export `{ scan, scanFile, discoverFiles, parseSource, enhanceReport, loadRules, rules, generateMarkdownReport, generateJsonReport, toSarif }`.
  - Allow developers to run:
    ```javascript
    import { scan } from 'trustlayer';
    const report = await scan('./src', { rules: [...] });
    ```
- [x] **Package Distribution Metadata:**
  - Configure `files` array in `package.json` to exclude tests, demo folders, and internal artifacts during `npm publish`.
  - Validate `"bin": { "trustlayer": "./src/cli.js" }` execution across Linux, macOS, and Windows.
- [x] **Windows Executable Compatibility:**
  - Verify Shebang `#!/usr/bin/env node` and CRLF/LF line ending compatibility.

---

## Module 6: Benchmark Harness & Demo Presentation Alignment

### 🎯 Objective
Equip the hackathon team with high-impact demonstration assets, benchmark numbers, and scripted talking points.

### 🔍 Scope & Target Files
- `scripts/benchmark.js` (New script)
- `scripts/demo-compare.js`
- Pitch alignment with `Artifacts/trustlayer-pitch-deck.md`

### 📋 Action Items
- [ ] **Benchmark Suite:**
  - Measure scan throughput (Files/sec, Lines of Code/sec, Memory footprint in MB).
  - Compare speed against typical SAST scan times (Semgrep ~12s vs TrustLayer ~0.3s).
- [ ] **Live Pitch Rehearsal Sequence:**
  - Step 1: Instant CLI scan on vulnerable demo (`demo/`).
  - Step 2: Show automated offline attack chain correlation.
  - Step 3: Run `npm run demo:compare` showing 8 vulnerabilities blocked in CI gate, 0 in remediated code.
  - Step 4: Show SARIF export for GitHub Security tab.

---

## Comprehensive Execution Prompts Catalog

Use the prompts below to execute each module independently with any AI coding agent or developer.

---

### 💬 Prompt 1: Code Hygiene & Dead Code Audit
```text
Role: Principal JavaScript Software Architect
Task: Perform a comprehensive dead code, unused export, and duplication audit on the TrustLayer repository.

Instructions:
1. Inspect all files in `src/engine/`, `src/utils/`, `src/rules/`, `src/types/`, and `src/cli.js`.
2. Identify:
   - Exported functions that are never imported anywhere in the project or tests.
   - Unused local variables, parameters, or imports across all modules.
   - Duplicate logic between `src/utils/ast-helpers.js`, `src/utils/patterns.js`, and individual rules in `src/rules/*.js`.
   - Any inconsistencies between JSDoc type contracts in `src/types/` and actual runtime objects.
3. Provide a detailed report of findings with exact line numbers and concrete refactoring suggestions.
4. Do NOT break existing tests. All 225 unit tests must remain passing.
```

---

### 💬 Prompt 2: AST Rule Precision & Webhook Exclusivity Hardening
```text
Role: Senior Application Security Engineer & AST Expert
Task: Audit and refine AST rules to eliminate false positives and handle realistic Express patterns.

Instructions:
1. Examine `src/rules/missing-auth-middleware.js` and `src/rules/missing-webhook-verification.js`:
   - Refine the logic so that dedicated webhook routes (e.g. routes containing '/webhook') do not trigger false positive "missing auth middleware" alerts when cryptographic signature verification is the intended security control.
2. Examine `src/rules/weak-crypto.js`:
   - Inspect `Math.random` detection. Ensure it checks surrounding variable naming and usage context to distinguish security-sensitive tokens/keys from benign UI math/styling.
3. Examine `src/rules/payment-amount-tampering.js`:
   - Check aliased/destructured input parameters (e.g. `const { amount: price } = req.body`).
4. Write targeted unit tests in `tests/rules/` verifying both true positives and the remediated false negative/positive edge cases.
5. Ensure `npm test` continues to pass with 100% success rate.
```

---

### 💬 Prompt 3: Scanner Defensive Audit (ReDoS, Symloops & Large Files)
```text
Role: Security Researcher / Static Analysis Engine Architect
Task: Audit TrustLayer's own engine for ReDoS vulnerabilities, resource exhaustion, and path traversal flaws.

Instructions:
1. Analyze every regular expression in `src/utils/patterns.js` and `src/rules/hardcoded-secrets.js` for catastrophic backtracking (ReDoS).
2. Check `src/engine/file-discovery.js`:
   - Verify handling of circular symlinks (`followSymbolicLinks`).
   - Add a default file-size ceiling (e.g. skip binary or huge minified files > 2MB with a debug warning).
3. Check `src/engine/ast-parser.js`:
   - Verify behavior when parsing non-JavaScript or heavily malformed inputs.
4. Add unit tests for edge-case files and ReDoS payload strings to ensure the scanner parses safely without hanging.
```

---

### 💬 Prompt 4: CLI Ergonomics & Robustness Hardening
```text
Role: CLI Tooling Engineer
Task: Audit and harden `src/cli.js` for optimal developer ergonomics and POSIX compliance.

Instructions:
1. Review all option flags in `src/cli.js`. Add shorthand `-a` for `--ai` to support user muscle memory and prevent `-ai` parsing errors.
2. Verify exit-code consistency across all scan outcomes:
   - Clean scan -> Exit code 0
   - Critical/High findings found -> Exit code 1
   - Syntax / Target not found -> Exit code 2
3. Audit error output formatting with Chalk/Ora spinners to guarantee clean terminal presentation even in non-TTY (CI/CD) environments.
4. Update `tests/cli.test.js` to assert the shorthand `-a` flag and verify error handling.
```

---

### 💬 Prompt 5: Phase 2 Programmatic Library API Implementation
```text
Role: Senior Node.js Library Maintainer
Task: Implement Phase 2 — Programmatic library entrypoint and distribution readiness for TrustLayer.

Instructions:
1. Create `src/index.js` exporting:
   - `scan(targetPath, options)`
   - `discoverFiles(targetPath, options)`
   - `parseSource(code, filePath)`
   - `enhanceReport(report, options)`
   - `loadRules(rulesDir)`
2. Ensure `src/index.js` can be imported in any modern ESM project without running the CLI banner or parsing `process.argv`.
3. Create `tests/engine/index.test.js` validating the programmatic API:
   - Running `scan('./demo')` returns a structured report object.
   - Programmatic options (severity filtering, category filtering, report generation) function identically to the CLI.
4. Review `package.json` to ensure `"files"`, `"main"`, and `"bin"` fields are properly configured for npm publishing.
```

---

### 💬 Prompt 6: Benchmark Suite & Hackathon Presentation Polish
```text
Role: Hackathon Technical Lead & Demo Producer
Task: Build a performance benchmark suite and solidify live demo assets.

Instructions:
1. Create `scripts/benchmark.js`:
   - Measure time taken to parse, traverse, and analyze varying codebase sizes (10 files, 50 files, 150 files).
   - Compute metrics: Files/sec, Lines/sec, AST Memory Delta (MB).
2. Ensure `npm run demo:compare` runs cleanly and outputs an ANSI table contrasting before vs after.
3. Validate alignment between generated reports, test metrics, and `Artifacts/trustlayer-pitch-deck.md`.
```
