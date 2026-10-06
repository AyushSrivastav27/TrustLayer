# AGENTS.md — Global Instructions for All AI Coding Agents 🤖

> **Target Audience:** Any AI assistant, coding agent, or LLM-powered tool (Cursor, Claude Code, GitHub Copilot, Gemini CLI, Antigravity, Aider, Windsurf, Roo, etc.) operating inside the **TrustLayer** repository.
> 
> **MANDATORY NOTICE TO AI AGENTS:** Before reading files, generating code, executing shell commands, or suggesting diffs, **YOU MUST READ AND ADHERE TO EVERY DIRECTIVE IN THIS DOCUMENT WITHOUT EXCEPTION.**

---

## 1. Project Context & Identity

- **Project Name:** TrustLayer
- **Repository:** `TrustLayer` (`vikalp1817243/TrustLayer`)
- **Domain:** Cybersecurity Hackathon — Theme: *"Shipped Fast, Left Open"*
- **Core Technology:** Node.js 20+ / Modern JavaScript (ES Modules) / `@babel/parser` / `@babel/traverse` / `Vitest` / `Commander.js`
- **Purpose:** A deterministic, framework-aware static security scanner targeting Node.js/Express APIs. It flags hardcoded secrets, injection flaws, missing auth guards, IDOR/BOLA patterns, and payment/transaction tampering before production deployment.

---

## 2. Hard Architectural Rules (DO NOT BREAK)

1. **NO Cross-File Taint Tracking:**
   - All static analysis is strictly **intra-file and intra-handler**.
   - Do NOT attempt to build an inter-procedural call-graph or resolve cross-module variable scopes across multiple files. Keep rules local and fast.
2. **Deterministic Rules FIRST, AI SECOND:**
   - The scanner **MUST fully function and produce all findings without an LLM or network connection.**
   - AI is **strictly additive**: used only to explain exploit scenarios, estimate impact, generate code remediation diffs, or correlate compound attack chains.
   - Never generate code where vulnerability detection relies solely on prompting an LLM.
3. **No Heavyweight or Native Parser Dependencies:**
   - Do NOT introduce Tree-sitter (native C-bindings hazard) or external SAST CLI wrappers (Semgrep, Bandit, ESLint CLI).
   - Use pure JavaScript tooling: `@babel/parser`, `@babel/traverse`, and `@babel/types`.
4. **Auto-Discovery Architecture:**
   - Security rules in `src/rules/*.js` are discovered dynamically by the engine via native ESM `import()`.
   - Never hardcode imports of individual rules into a central static array or index file.

---

## 3. Strict File Ownership Boundaries

Every human developer and their AI assistant is assigned a specific, non-overlapping boundary. **AI agents MUST determine which human developer they are assisting and NEVER edit files outside that developer's ownership:**

| Team Role | Assigned Branch | Allowed Files to Edit / Create |
|---|---|---|
| **Member 1 (Team Lead)** | `main` | `src/engine/*`, `src/cli.js`, `src/types/*`, `src/utils/*`, `demo/server.js`, `demo/db/*`, configs |
| **Member 2** | `feature/secrets-crypto` | `src/rules/hardcoded-secrets.js`, `src/rules/weak-crypto.js`, `tests/rules/hardcoded-secrets.test.js`, `tests/rules/weak-crypto.test.js` |
| **Member 3** | `feature/injection-rules` | `src/rules/sql-injection.js`, `src/rules/missing-input-validation.js`, `tests/rules/sql-injection.test.js`, `tests/rules/missing-input-validation.test.js` |
| **Member 4** | `feature/auth-payment-rules` | `src/rules/payment-amount-tampering.js`, `src/rules/missing-webhook-verification.js`, `src/rules/missing-auth-middleware.js`, `tests/rules/payment-*.test.js`, `tests/rules/auth-*.test.js` |
| **Member 5** | `feature/demo-reporting` | `src/reporters/*`, `src/ai/*`, `demo/routes/*`, `demo/middleware/*`, `demo-fixed/*`, `tests/reporters/*` |

### ⛔ Agent Forbidden Actions:
- ❌ **NEVER modify `src/types/rule.js` or `src/types/finding.js`** unless explicitly confirmed that you are assisting the Team Lead.
- ❌ **NEVER modify `package.json` or `package-lock.json`** without explicit human prompt.
- ❌ **NEVER add new npm dependencies** without prior user confirmation.
- ❌ **NEVER run `git push origin main` or execute terminal merges (`git merge`).**

---

## 4. The `Rule` Contract (The Core Interface)

Every rule created by an agent in `src/rules/*.js` **MUST implement and export as `default`** the structure defined below:

```javascript
/**
 * @typedef {import('../types/rule.js').Rule} Rule
 */

/** @type {Rule} */
const exampleRule = {
  id: 'category/kebab-case-name', // e.g. 'payment/client-controlled-amount'
  name: 'Human Readable Title',
  severity: 'critical',           // 'critical' | 'high' | 'medium' | 'low'
  category: 'payment',            // 'secrets' | 'injection' | 'payment' | 'auth'
  description: 'Concise summary of what pattern is flagged.',
  defaultExplanation: 'Detailed explanation used when LLM is unavailable.',
  defaultRemediation: 'Code example demonstrating the secure pattern.',
  analyze(context) {
    const findings = [];
    const { filePath, fileContent, ast, lines } = context;

    if (!ast) return findings;

    // Use @babel/traverse on the AST passed in the context
    // Never parse the file manually within analyze()
    
    return findings;
  }
};

export default exampleRule;
```

### AnalysisContext Guarantees:
- `ast`: A pre-parsed `@babel/parser` AST. If `ast` is `null`, the file is not JavaScript.
- `lines`: The file source split by newline for instant line referencing.
- `fileContent`: Raw string content of the file.
- `filePath`: Relative or absolute path to the file under scan.

---

## 5. Coding & Testing Standards

- **Language:** Node.js 20+ with Modern JavaScript (ES Modules, `"type": "module"`).
- **No Build Step:** Runs directly with `node src/cli.js` without transpilation.
- **AST Safety:** Always verify node types using `@babel/types` helper guards (`t.isIdentifier(node)`, `t.isMemberExpression(node)`) before reading properties.
- **Unit Testing (Vitest):** Every single rule must be paired with a Vitest file in `tests/rules/<rule-name>.test.js` containing:
  1. **True Positive:** Detects a clearly vulnerable snippet.
  2. **True Negative:** Ignores safe/remediated code without false positives.
  3. **Edge Case:** Handles missing properties, alternative function names, or empty functions gracefully without throwing errors.

---

## 6. Git Protocol for AI Agents

When assisting a developer with Git commands:
1. Always verify the current branch with `git status` or `git branch --show-current`.
2. Ensure the working branch matches the developer's assigned role from Section 3.
3. Recommend staging only specific files (`git add src/rules/...`), never blindly staging everything with `git add .` or `git add -A`.
4. Ensure `npm test` runs and passes before suggesting a commit or push.
5. All pull requests must be directed towards `main` on the upstream repository.

---

## 7. Reference Files for Deep Context

When in doubt, consult these master documents:
- `Artifacts/implementation_plan.md` — Complete master technical specifications, visitor patterns, and competitor analysis.
- `Artifacts/trustlayer-pitch-deck.md` — The hackathon problem statement alignment and demo story.
- `CLAUDE.md` / `GEMINI.md` — Framework-specific assistant directives.
- `CONTRIBUTING.md` — Teammate human workflow and GitHub collaboration guidelines.
