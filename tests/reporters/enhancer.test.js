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

describe('M5-5 & M5-6 Verification: Cache Isolation & Modern OpenAI Key Contradiction Tests', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    clearCache();
    globalThis.fetch = originalFetch;
  });

  it('contradiction test (M5-5): clearCache() reliably evicts cached responses to prevent test leakage', async () => {
    let mockFetchCalls = 0;
    globalThis.fetch = async () => {
      mockFetchCalls++;
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: `Mock Response #${mockFetchCalls}` } }]
        })
      };
    };

    const finding = {
      ruleId: 'payment/payment-amount-tampering',
      severity: 'critical'
    };
    const codeContext = 'stripe.charges.create({ amount: req.body.amount })';

    // 1. Initial call (cache miss -> invokes mock fetch)
    const res1 = await enhanceFinding(finding, codeContext, { apiKey: 'sk-proj-test-key' });
    expect(res1.aiExplanation).toBe('Mock Response #1');
    expect(mockFetchCalls).toBe(1);

    // 2. Second call with identical key/snippet (cache hit -> returns cached, mockFetchCalls NOT incremented)
    const res2 = await enhanceFinding(finding, codeContext, { apiKey: 'sk-proj-test-key' });
    expect(res2.aiExplanation).toBe('Mock Response #1');
    expect(mockFetchCalls).toBe(1);

    // 3. Evict cache via clearCache()
    clearCache();

    // 4. Third call (must be fresh fetch; if it returned #1, it would contradict cache eviction)
    const res3 = await enhanceFinding(finding, codeContext, { apiKey: 'sk-proj-test-key' });
    expect(res3.aiExplanation).toBe('Mock Response #2');
    expect(mockFetchCalls).toBe(2);
  });

  it('contradiction test (M5-6): routes all modern OpenAI key prefixes (sk-, sk-proj-, sk-org-) to chat endpoint', async () => {
    const requestedUrls = [];
    globalThis.fetch = async (url) => {
      requestedUrls.push(url);
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: 'LLM explanation' } }]
        })
      };
    };

    const modernKeys = [
      'sk-proj-abc1234567890XYZ',
      'sk-org-org1234567890XYZ',
      'sk-traditional1234567890'
    ];

    for (const apiKey of modernKeys) {
      clearCache();
      const finding = { ruleId: `test/rule-${apiKey.slice(0, 7)}`, severity: 'high' };
      await enhanceFinding(finding, 'code snippet', { apiKey });
    }

    // Contradiction assertion: All 3 modern formats must route to the OpenAI chat completions URL
    expect(requestedUrls).toHaveLength(3);
    for (const url of requestedUrls) {
      expect(url).toBe('https://api.openai.com/v1/chat/completions');
    }

    // Non-matching key should not route to OpenAI
    requestedUrls.length = 0;
    clearCache();
    await enhanceFinding({ ruleId: 'test/non-ai', severity: 'low' }, 'code', { apiKey: 'random-unknown-token' });
    expect(requestedUrls).toHaveLength(0);
  });

  it('worst-case scenario: API network failure or abort timeout degrades gracefully without throwing', async () => {
    globalThis.fetch = async () => {
      throw new Error('Network offline or request timed out');
    };

    const finding = {
      ruleId: 'crypto/weak-crypto',
      severity: 'high',
      message: 'Weak MD5 algorithm detected'
    };

    // Must not reject or throw
    const res = await enhanceFinding(finding, 'code', { apiKey: 'sk-proj-test-key' });
    expect(res).toBeDefined();
    expect(res.ruleId).toBe('crypto/weak-crypto');
    expect(res.aiExploitScenario).toBeDefined();
  });

  it('worst-case scenario: malformed API responses (empty choices, non-JSON) degrade gracefully', async () => {
    // 1. Empty choices array
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [] })
    });

    const finding = { ruleId: 'injection/sql-injection', severity: 'critical' };
    const res1 = await enhanceFinding(finding, 'code', { apiKey: 'sk-proj-test-key' });
    expect(res1.ruleId).toBe('injection/sql-injection');
    expect(res1.aiExploitScenario).toContain('SQL payload');

    // 2. HTTP 500 error
    clearCache();
    globalThis.fetch = async () => ({
      ok: false,
      status: 500
    });
    const res2 = await enhanceFinding(finding, 'code', { apiKey: 'sk-proj-test-key' });
    expect(res2.ruleId).toBe('injection/sql-injection');
  });
});

