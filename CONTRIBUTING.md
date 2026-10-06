# Contributing to TrustLayer 🛡️

Welcome to **TrustLayer**! We are building a high-impact, AST-powered static security scanner for the hackathon. 

To ensure **zero merge conflicts**, clean commits, and smooth integration under tight deadlines, **all team members must strictly follow this guide.**

---

## ⚠️ The Golden Rules (Read First!)

1. **NEVER push directly to the `main` branch.** `main` is protected.
2. **NEVER merge branches locally on your terminal.** All merges are done via GitHub Pull Requests (PRs).
3. **ONLY the Team Lead (Vikalp) reviews and merges PRs.**
4. **STRICT File Ownership:** Do not touch or edit files assigned to other team members. If you need a change in someone else's module, request it via PR comments or team chat.
5. **Always test before opening a PR.** Code that breaks existing tests will not be merged.

---

## 👥 Module Ownership & Responsibilities

Find your assigned feature branch, files, and deliverables below:

| Role | Branch Name | Files You Own (Edit ONLY these) | Deliverable / Responsibility |
|---|---|---|---|
| **Member 1 (Team Lead)** | `main` | `src/engine/`, `src/cli.js`, `src/types/`, `src/utils/`, `demo/server.js`, `demo/db/` | Core Babel engine, CLI orchestrator, `Rule` contract, PR review & integration |
| **Member 2** | `feature/secrets-crypto` | `src/rules/hardcoded-secrets.js`, `src/rules/weak-crypto.js`, `tests/rules/hardcoded-secrets.test.js`, `tests/rules/weak-crypto.test.js` | Secret scanning (regex + Shannon entropy) & weak crypto detection |
| **Member 3** | `feature/injection-rules` | `src/rules/sql-injection.js`, `src/rules/missing-input-validation.js`, `tests/rules/sql-injection.test.js`, `tests/rules/missing-input-validation.test.js` | AST rules for SQL injection & unsafe execution (`eval`, `child_process.exec`) |
| **Member 4** | `feature/auth-payment-rules` | `src/rules/payment-amount-tampering.js`, `src/rules/missing-webhook-verification.js`, `src/rules/missing-auth-middleware.js`, `tests/rules/payment-*.test.js`, `tests/rules/auth-*.test.js` | AST source→sink payment tampering, webhook HMAC verification & missing route auth |
| **Member 5** | `feature/demo-reporting` | `src/reporters/`, `src/ai/`, `demo/routes/`, `demo-fixed/`, `tests/reporters/` | Vulnerable & fixed demo apps (`QuickSaaS`), Markdown & SARIF report generators, AI explanation layer |

---

## 🚀 Step-by-Step GitHub Workflow

### Step 1: Fork or Clone the Repository

#### Option A: If using a Shared Repository
If the team lead gave you direct collaborator access to the repo:
```bash
# Clone the repository
git clone https://github.com/vikalp1817243/TrustLayer.git
cd TrustLayer
```

#### Option B: If Forking (Recommended for Fork Workflow)
1. Go to the main GitHub repository URL.
2. Click the **"Fork"** button (top-right corner) to create a copy under your personal GitHub account.
3. Clone your fork locally:
   ```bash
   git clone https://github.com/<YOUR-USERNAME>/TrustLayer.git
   cd TrustLayer
   ```
4. Set up the upstream remote to sync changes from the lead's repository:
   ```bash
   git remote add upstream https://github.com/vikalp1817243/TrustLayer.git
   git fetch upstream
   ```

---

### Step 2: Install Dependencies
Make sure you are using **Node.js 20+**:
```bash
npm install
```

---

### Step 3: Create Your Feature Branch
**Always branch out from the latest `main` branch:**

```bash
# 1. Ensure you are on main and up to date
git checkout main
git pull upstream main   # or 'git pull origin main' if working on shared repo

# 2. Create and switch to your designated feature branch
# Replace with your assigned branch name:
git checkout -b feature/secrets-crypto
```

---

### Step 4: Implement Your Assigned Component
- Work strictly inside your assigned directory/files (see ownership table above).
- Every security rule must export a default object complying with the rule structure:
  ```javascript
  const myRule = {
    id: 'category/rule-name',
    name: 'Rule Human Readable Name',
    severity: 'critical', // 'critical' | 'high' | 'medium' | 'low'
    category: 'secrets',  // 'secrets' | 'injection' | 'payment' | 'auth'
    description: 'Brief explanation of what this detects',
    defaultExplanation: 'Detailed impact when AI is unavailable',
    defaultRemediation: 'Code example showing how to fix',
    analyze(context) {
      const findings = [];
      // AST or regex logic here
      return findings;
    }
  };

  export default myRule;
  ```

---

### Step 5: Test Your Code Locally
Never push unverified code. Run test suites locally:

```bash
# Run all tests
npm test

# Run only your specific test file
npx vitest run tests/rules/your-rule-name.test.js
```

Every rule must include at least **3 unit tests**:
1. **True Positive:** Detects a clearly vulnerable code snippet.
2. **True Negative:** Ignores safe/sanitized code without false alarms.
3. **Edge Case:** Handles syntax variations or benign constants safely.

---

### Step 6: Commit and Push to GitHub

Write clear, descriptive commit messages:

```bash
# Stage only your assigned files
git add src/rules/hardcoded-secrets.js tests/rules/hardcoded-secrets.test.js

# Commit with a clean message
git commit -m "feat(secrets): implement regex and Shannon entropy scanner for API keys"

# Push branch to your GitHub remote
git push origin feature/secrets-crypto
```

---

### Step 7: Open a Pull Request (PR) on GitHub

1. Go to the original repository on GitHub in your browser.
2. You will see a banner: **"Compare & pull request"**. Click it.
3. Verify the base and compare branches:
   - **Base branch:** `main` (on the lead's upstream repo)
   - **Compare branch:** `feature/<your-branch-name>`
4. Title your PR clearly:
   - `feat(secrets): add hardcoded secrets and weak crypto detection rules`
   - `feat(injection): add SQL injection AST source-to-sink rule`
5. Fill out the PR template checklist (copy below into PR description):

```markdown
### PR Summary
- [ ] What rule or feature does this PR implement?
- [ ] Files modified / created:

### Quality Checklist
- [ ] Code strictly stays within my assigned file boundaries.
- [ ] Implements the `Rule` contract (`src/types/rule.js`).
- [ ] Exported as `export default myRule`.
- [ ] Added unit tests (true positive, true negative, edge case).
- [ ] `npm test` passes with zero errors.
- [ ] No local merge commits or terminal rebases against `main`.
```

6. Click **"Create Pull Request"**.
7. Notify the Team Lead on WhatsApp / Discord / Slack with the PR link.

---

## 🔄 Keeping Your Branch in Sync (Avoid Conflicts)

As other members' PRs get merged into `main`, your branch might fall behind. **Sync safely without breaking history:**

```bash
# 1. Fetch latest changes from main
git checkout main
git pull upstream main

# 2. Switch back to your feature branch
git checkout feature/<your-branch-name>

# 3. Rebase your work on top of latest main
git rebase main

# If any conflict occurs in files you do NOT own, abort immediately and consult the lead:
# git rebase --abort

# 4. Push updated branch to your remote (force-with-lease is safe on personal feature branches)
git push origin feature/<your-branch-name> --force-with-lease
```

---

## 🚫 Common Mistakes to Avoid

| What NOT to do | Why it breaks things | What to do instead |
|---|---|---|
| `git push origin main` | Fails or overwrites team code | Always push to `feature/<name>` |
| `git merge main` into local main | Creates messy criss-cross merge commits | Let GitHub handle merges via PR |
| Modifying `src/types/rule.js` | Breaks team-wide type contracts | Request type additions from the Team Lead |
| Modifying `package.json` | Causes npm dependency lock conflicts | Ask Team Lead before adding new npm packages |
| Pushing without running `npm test` | Breaks CI/CD builds for the entire team | Run `npm test` before every commit |

---

## ❓ Need Help?
- **Build / Type Errors:** Post a screenshot and the exact terminal log to the team group.
- **Rule Guidance:** Check `Artifacts/implementation_plan.md` for exact AST visitor patterns and source/sink signatures.
- **Urgent PR Review:** Ping `@Vikalp` on the team channel.
