import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { scan } from '../../src/engine/scanner.js';
import { enhanceReport } from '../../src/ai/enhancer.js';
import { generateMarkdownReport } from '../../src/reporters/markdown-reporter.js';

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
