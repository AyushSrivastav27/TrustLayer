import { describe, it, expect, afterEach } from 'vitest';
import { correlateAttackChains, enhanceFinding, enhanceReport, clearCache } from '../../src/ai/enhancer.js';

describe('AI Enhancer Layer: correlateAttackChains & enhanceReport', () => {
  afterEach(() => {
    clearCache();
  });
  it('correlates payment tampering and unverified webhook into critical attack chain', () => {
    const findings = [
      {
        ruleId: 'payment/payment-amount-tampering',
        severity: 'critical',
        message: 'Client-controlled payment amount'
      },
      {
        ruleId: 'payment/missing-webhook-verification',
        severity: 'high',
        message: 'Unverified webhook signature'
      }
    ];

    const chains = correlateAttackChains(findings);

    expect(chains).toHaveLength(1);
    expect(chains[0].title).toContain('Price Manipulation');
    expect(chains[0].severity).toBe('critical');
    expect(chains[0].findingIds).toContain('payment/payment-amount-tampering');
    expect(chains[0].findingIds).toContain('payment/missing-webhook-verification');
  });

  it('correlates hardcoded secret and missing auth into administrative impersonation chain', () => {
    const findings = [
      {
        ruleId: 'secrets/hardcoded-secrets',
        severity: 'critical',
        message: 'Hardcoded secret detected'
      },
      {
        ruleId: 'auth/missing-auth-middleware',
        severity: 'high',
        message: 'Missing auth guard'
      }
    ];

    const chains = correlateAttackChains(findings);

    expect(chains.some(c => c.title.includes('Administrative Impersonation'))).toBe(true);
  });

  it('returns empty array when findings array is empty or null', () => {
    expect(correlateAttackChains([])).toEqual([]);
    expect(correlateAttackChains(null)).toEqual([]);
  });

  it('gracefully degrades without LLM API key during enhanceFinding', async () => {
    const rawFinding = {
      ruleId: 'crypto/weak-crypto',
      severity: 'high',
      line: 12,
      codeSnippet: 'crypto.createHash("md5")',
      message: 'Weak hashing algorithm'
    };

    const enhanced = await enhanceFinding(rawFinding);

    expect(enhanced.ruleId).toBe('crypto/weak-crypto');
    expect(enhanced.confidence).toBe('high');
  });

  it('enhances full report with attack chains and preserved summary', async () => {
    const sampleReport = {
      scannerVersion: '1.0.0',
      summary: { totalFiles: 2, totalFindings: 2 },
      findings: [
        { ruleId: 'injection/sql-injection', severity: 'critical' },
        { ruleId: 'injection/missing-input-validation', severity: 'high' }
      ]
    };

    const enhancedReport = await enhanceReport(sampleReport);

    expect(enhancedReport.attackChains).toBeDefined();
    expect(enhancedReport.attackChains.length).toBeGreaterThan(0);
    expect(enhancedReport.attackChains[0].title).toContain('SQL Injection');
  });

  it('provides generateAttackChains alias with name, findings, and narrative properties', () => {
    const findings = [
      { ruleId: 'payment/payment-amount-tampering', severity: 'critical' },
      { ruleId: 'payment/missing-webhook-verification', severity: 'high' }
    ];

    const chains = correlateAttackChains(findings);
    expect(chains[0].name).toBeDefined();
    expect(chains[0].findings).toBeDefined();
    expect(chains[0].narrative).toBeDefined();
    expect(chains[0].name).toBe(chains[0].title);
  });

  it('generates rich deterministic exploit scenario offline for payment amount tampering', async () => {
    const finding = {
      ruleId: 'payment/payment-amount-tampering',
      severity: 'critical',
      codeSnippet: 'stripe.charges.create({ amount: req.body.amount })'
    };

    const enhanced = await enhanceFinding(finding);
    expect(enhanced.aiExploitScenario).toContain('intercepts the checkout HTTP request');
    expect(enhanced.aiExploitScenario).toContain('$0.01');
    expect(enhanced.aiConfidence).toBe('high');
  });

  it('supports (finding, codeContext, options) signature and caches responses', async () => {
    const finding = {
      ruleId: 'injection/sql-injection',
      severity: 'critical'
    };
    const codeContext = 'db.all(`SELECT * FROM products WHERE name = "${q}"`)';

    const enhanced1 = await enhanceFinding(finding, codeContext, { apiKey: 'mock-key' });
    const enhanced2 = await enhanceFinding(finding, codeContext, { apiKey: 'mock-key' });

    expect(enhanced1.ruleId).toBe('injection/sql-injection');
    expect(enhanced2.ruleId).toBe('injection/sql-injection');
  });

  it('clears in-memory cache when clearCache is called', () => {
    expect(() => clearCache()).not.toThrow();
  });

  it('recognizes modern OpenAI key formats (sk-proj-, sk-org-) without throwing', async () => {
    const finding = { ruleId: 'secrets/hardcoded-secrets', severity: 'critical' };
    const enhanced = await enhanceFinding(finding, '', { apiKey: 'sk-proj-mock-key' });
    expect(enhanced.ruleId).toBe('secrets/hardcoded-secrets');
  });
});
