import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  correlateAttackChains,
  enhanceFinding,
  enhanceReport,
  extractJsonFromResponse,
  clearCache,
  DEFAULT_GEMINI_MODEL,
  getDeterministicRemediation
} from '../../src/ai/enhancer.js';

describe('AI Enhancer Layer: correlateAttackChains & enhanceReport', () => {
  afterEach(() => {
    clearCache();
    vi.restoreAllMocks();
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
    expect(enhanced.aiMode).toBe('offline');
    expect(enhanced.aiEngine).toBe('Deterministic Heuristics');
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
    expect(enhancedReport.aiMode).toBe('offline');
    expect(enhancedReport.aiEngine).toBe('Deterministic Heuristics');
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
    expect(enhanced.aiMode).toBe('offline');
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

  it('parses structured JSON from various raw LLM output shapes', () => {
    // Direct JSON
    const direct = extractJsonFromResponse('{"exploitScenario": "step 1", "businessImpact": "loss"}');
    expect(direct).toEqual({ exploitScenario: 'step 1', businessImpact: 'loss' });

    // Markdown fence ```json
    const fenced = extractJsonFromResponse('Here is the analysis:\n```json\n{"exploitScenario": "step 2"}\n```');
    expect(fenced).toEqual({ exploitScenario: 'step 2' });

    // Embedded braces
    const embedded = extractJsonFromResponse('Output:\n{"exploitScenario": "step 3"}\nDone.');
    expect(embedded).toEqual({ exploitScenario: 'step 3' });

    // Invalid string
    expect(extractJsonFromResponse('No json here')).toBeNull();
    expect(extractJsonFromResponse(null)).toBeNull();
  });

  it('extracts structured online response when Gemini API succeeds', async () => {
    const mockJson = {
      exploitScenario: '1. Attacker sends forged payload.\n2. Server executes without validation.',
      businessImpact: 'Complete account takeover and unauthorized funds transfer.',
      remediation: 'const validated = schema.parse(req.body);'
    };

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        candidates: [
          {
            content: {
              parts: [{ text: JSON.stringify(mockJson) }]
            }
          }
        ]
      })
    });
    vi.stubGlobal('fetch', mockFetch);

    const finding = {
      ruleId: 'payment/payment-amount-tampering',
      severity: 'critical',
      codeSnippet: 'stripe.charges.create({ amount: req.body.amount })'
    };

    const enhanced = await enhanceFinding(finding, '', {
      apiKey: 'AIzaSyFakeKey123'
    });

    expect(enhanced.aiMode).toBe('online');
    expect(enhanced.aiEngine).toContain(DEFAULT_GEMINI_MODEL);
    expect(enhanced.aiExploitScenario).toBe(mockJson.exploitScenario);
    expect(enhanced.aiExplanation).toBe(mockJson.businessImpact);
    expect(enhanced.aiRemediation).toBe(mockJson.remediation);
  });

  it('provides deterministic remediation code for all canonical vulnerability rules', () => {
    const rules = [
      'payment/payment-amount-tampering',
      'payment/missing-webhook-verification',
      'secrets/hardcoded-secrets',
      'auth/missing-auth-middleware',
      'injection/sql-injection',
      'injection/missing-input-validation',
      'crypto/weak-crypto'
    ];

    for (const ruleId of rules) {
      const remediation = getDeterministicRemediation(ruleId);
      expect(remediation).toBeDefined();
      expect(typeof remediation).toBe('string');
      expect(remediation.length).toBeGreaterThan(20);
    }
  });

  it('handles JSON with trailing commas gracefully in extractJsonFromResponse', () => {
    const jsonWithTrailing = '{\n  "exploitScenario": "step with comma",\n  "businessImpact": "impact",\n}';
    const parsed = extractJsonFromResponse(jsonWithTrailing);
    expect(parsed).toEqual({
      exploitScenario: 'step with comma',
      businessImpact: 'impact'
    });
  });

  it('enriches offline findings with deterministic remediation code when rule has minimal remediation', async () => {
    const finding = {
      ruleId: 'payment/missing-webhook-verification',
      severity: 'high'
    };

    const enhanced = await enhanceFinding(finding);
    expect(enhanced.aiMode).toBe('offline');
    expect(enhanced.aiRemediation).toContain('constructEvent');
    expect(enhanced.remediation).toContain('constructEvent');
  });
});

