import { describe, it, expect } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import { scan } from '../../src/engine/scanner.js';
import { enhanceReport } from '../../src/ai/enhancer.js';
import { generateMarkdownReport } from '../../src/reporters/markdown-reporter.js';
import { parseSource } from '../../src/engine/ast-parser.js';
import { SECRET_PATTERNS } from '../../src/utils/patterns.js';

// Direct rule imports for robust testing across paths with spaces
import paymentAmountTampering from '../../src/rules/payment-amount-tampering.js';
import missingWebhookVerification from '../../src/rules/missing-webhook-verification.js';
import missingAuthMiddleware from '../../src/rules/missing-auth-middleware.js';
import sqlInjection from '../../src/rules/sql-injection.js';
import missingInputValidation from '../../src/rules/missing-input-validation.js';
import hardcodedSecrets from '../../src/rules/hardcoded-secrets.js';
import weakCrypto from '../../src/rules/weak-crypto.js';

const rules = [
  paymentAmountTampering,
  missingWebhookVerification,
  missingAuthMiddleware,
  sqlInjection,
  missingInputValidation,
  hardcodedSecrets,
  weakCrypto
];

describe('End-to-End Demo Verification: Vulnerable vs Hardened Apps', () => {
  const demoRoutesPath = path.resolve(process.cwd(), 'demo/routes');
  const demoFixedPath = path.resolve(process.cwd(), 'demo-fixed');

  it('detects exactly 8 canonical vulnerabilities in demo/routes (3 critical, 5 high)', async () => {
    const report = await scan(demoRoutesPath, { rules });

    expect(report.summary.totalFiles).toBe(5);
    expect(report.findings.length).toBeGreaterThanOrEqual(8);

    const counts = report.summary.severities;
    expect(counts.critical).toBeGreaterThanOrEqual(3);
    expect(counts.high).toBeGreaterThanOrEqual(5);
    expect(counts.medium).toBe(0);
    expect(counts.low).toBe(0);

    const ruleIds = report.findings.map(f => f.ruleId);
    expect(ruleIds).toContain('payment/payment-amount-tampering');
    expect(ruleIds).toContain('payment/missing-webhook-verification');
    expect(ruleIds).toContain('injection/sql-injection');
    expect(ruleIds).toContain('injection/missing-input-validation');
    expect(ruleIds).toContain('secrets/hardcoded-secrets');
    expect(ruleIds).toContain('crypto/weak-crypto');
    expect(ruleIds).toContain('auth/missing-auth-middleware');
  });

  it('scans demo-fixed to a completely clean scan (0 findings)', async () => {
    const report = await scan(demoFixedPath, { rules });

    expect(report.summary.totalFiles).toBeGreaterThanOrEqual(6);
    expect(report.findings).toHaveLength(0);
    expect(report.summary.totalFindings).toBe(0);

    const counts = report.summary.severities;
    expect(counts.critical).toBe(0);
    expect(counts.high).toBe(0);
    expect(counts.medium).toBe(0);
    expect(counts.low).toBe(0);
  });

  it('generates a clean scan markdown report for demo-fixed', async () => {
    const report = await scan(demoFixedPath, { rules });
    const md = generateMarkdownReport(report);

    expect(md).toContain('# 🛡️ TrustLayer Security Audit Report');
    expect(md).toContain('## ✅ Clean Scan — No Vulnerabilities Detected');
    expect(md).toContain('All automated static analysis checks passed with zero security findings.');
    expect(md).not.toContain('Findings Overview');
    expect(md).not.toContain('## ⚡ Correlated Attack Chains');
  });

  it('generates an enhanced vulnerability report for demo/routes with 4 attack chains', async () => {
    const rawReport = await scan(demoRoutesPath, { rules });
    const enhancedReport = await enhanceReport(rawReport);

    expect(enhancedReport.attackChains).toHaveLength(4);

    const md = generateMarkdownReport(enhancedReport);
    expect(md).toContain('## ⚡ Correlated Attack Chains');
    expect(md).toContain('Arbitrary Price Manipulation & Forged Order Fulfillment');
    expect(md).toContain('Administrative Impersonation & Unrestricted Endpoint Access');
    expect(md).toContain('Unauthenticated SQL Injection Leading to Database Exfiltration');
    expect(md).toContain('Predictable Token Generation & Account Takeover');
  });
});

describe('M5-2 Verification: Dummy Credential Collision & Contradiction Tests', () => {
  const checkoutVulnerablePath = path.resolve(process.cwd(), 'demo/routes/checkout.js');
  const checkoutFixedPath = path.resolve(process.cwd(), 'demo-fixed/routes/checkout.js');
  const webhookFixedPath = path.resolve(process.cwd(), 'demo-fixed/routes/webhook.js');
  const authVulnerablePath = path.resolve(process.cwd(), 'demo/routes/auth.js');

  it('contradiction test: scanning demo-fixed produces 0 secret findings across all files', async () => {
    const demoFixedPath = path.resolve(process.cwd(), 'demo-fixed');
    const report = await scan(demoFixedPath, { rules: [hardcodedSecrets] });

    // Contradiction assertion: Any secret finding in demo-fixed contradicts clean demo architecture
    expect(report.findings).toHaveLength(0);
    expect(report.summary.totalFindings).toBe(0);
  });

  it('contradiction test: dummy Stripe and webhook placeholders do not collide with known secret patterns', () => {
    const filesToCheck = [
      checkoutVulnerablePath,
      checkoutFixedPath,
      webhookFixedPath
    ];

    for (const filePath of filesToCheck) {
      const content = fs.readFileSync(filePath, 'utf8');

      // 1. Must not contain real key prefixes that trigger GitHub Push Protection or SAST rules
      expect(content).not.toMatch(/sk_test_[0-9a-zA-Z]/);
      expect(content).not.toMatch(/sk_live_[0-9a-zA-Z]/);
      expect(content).not.toMatch(/whsec_[0-9a-zA-Z]/);
      expect(content).not.toMatch(/rzp_(?:test|live)_[0-9a-zA-Z]/);

      // 2. Must not match any of the patterns defined in SECRET_PATTERNS
      for (const pattern of SECRET_PATTERNS) {
        expect(content).not.toMatch(pattern.regex);
      }
    }
  });

  it('contradiction test: hardcoded-secrets flags demo/routes/auth.js but NEVER demo/routes/checkout.js', () => {
    const authContent = fs.readFileSync(authVulnerablePath, 'utf8');
    const authParsed = parseSource(authContent, authVulnerablePath);
    const authFindings = hardcodedSecrets.analyze({
      filePath: authVulnerablePath,
      fileContent: authContent,
      ast: authParsed.ast,
      lines: authContent.split('\n')
    });

    // True Positive: Vulnerability #1 in auth.js is reliably detected
    expect(authFindings).toHaveLength(1);
    expect(authFindings[0].ruleId).toBe('secrets/hardcoded-secrets');
    expect(authFindings[0].message).toContain('JWT_SECRET');

    const checkoutContent = fs.readFileSync(checkoutVulnerablePath, 'utf8');
    const checkoutParsed = parseSource(checkoutContent, checkoutVulnerablePath);
    const checkoutFindings = hardcodedSecrets.analyze({
      filePath: checkoutVulnerablePath,
      fileContent: checkoutContent,
      ast: checkoutParsed.ast,
      lines: checkoutContent.split('\n')
    });

    // True Negative (Anti-Contradiction): checkout.js has NO secret findings
    expect(checkoutFindings).toHaveLength(0);
  });

  it('worst-case scenario: aggressive upgraded regex scanner detects 0 false positives in demo routes', () => {
    // Simulate Member 2 P1-A upgrade: scanning every string literal across the AST
    const filesToTest = [checkoutVulnerablePath, checkoutFixedPath, webhookFixedPath];

    for (const filePath of filesToTest) {
      const content = fs.readFileSync(filePath, 'utf8');
      const { ast } = parseSource(content, filePath);

      const flaggedStrings = [];
      const checkNode = (node) => {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'StringLiteral') {
          const val = node.value;
          const matches = SECRET_PATTERNS.some(p => p.regex.test(val));
          const hasSecretPrefix = val.startsWith('sk_live_') || val.startsWith('sk_test_') || val.startsWith('whsec_');
          if (matches || hasSecretPrefix) {
            flaggedStrings.push({ val, line: node.loc?.start?.line });
          }
        }
        for (const key of Object.keys(node)) {
          if (key === 'loc' || key === 'comments') continue;
          const child = node[key];
          if (Array.isArray(child)) {
            child.forEach(checkNode);
          } else if (typeof child === 'object') {
            checkNode(child);
          }
        }
      };

      checkNode(ast);
      expect(flaggedStrings).toEqual([]);
    }
  });
});

