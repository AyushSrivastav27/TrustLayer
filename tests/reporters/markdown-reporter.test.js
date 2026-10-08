import { describe, it, expect } from 'vitest';
import { generateMarkdownReport } from '../../src/reporters/markdown-reporter.js';

describe('Reporter: markdown-reporter', () => {
  const sampleReport = {
    scannerVersion: '1.0.0',
    scanDate: '2026-10-07T12:00:00.000Z',
    targetDirectory: '/projects/quickshop',
    summary: {
      totalFiles: 5,
      totalFindings: 2,
      severities: { critical: 1, high: 1, medium: 0, low: 0 },
      scanDurationMs: 140
    },
    findings: [
      {
        ruleId: 'payment/payment-amount-tampering',
        severity: 'critical',
        file: '/projects/quickshop/routes/checkout.js',
        line: 18,
        column: 7,
        codeSnippet: 'const charge = await stripe.charges.create({ amount: req.body.amount });',
        message: 'Client-controlled payment amount detected',
        explanation: 'Allowing untrusted input to specify the payment amount enables price tampering.',
        remediation: 'Lookup product prices on the server and calculate total server-side.',
        confidence: 'high'
      },
      {
        ruleId: 'auth/missing-auth-middleware',
        severity: 'high',
        file: '/projects/quickshop/routes/orders.js',
        line: 10,
        column: 1,
        codeSnippet: 'router.get("/:id", (req, res) => { ... });',
        message: 'Sensitive route lacks authentication middleware',
        explanation: 'Unprotected endpoints allow unauthorized data access.',
        remediation: 'Attach requireAuth middleware to the route chain.',
        confidence: 'high'
      }
    ],
    attackChains: [
      {
        title: 'Tampered Checkout to Privilege Escalation',
        description: 'An attacker modifies price during checkout and accesses order records.',
        findingIds: ['payment/payment-amount-tampering', 'auth/missing-auth-middleware'],
        severity: 'critical'
      }
    ]
  };

  it('renders report header, target, and executive summary table', () => {
    const md = generateMarkdownReport(sampleReport);

    expect(md).toContain('# 🛡️ TrustLayer Security Audit Report');
    expect(md).toContain('/projects/quickshop');
    expect(md).toContain('**5** files');
    expect(md).toContain('140ms');
    expect(md).toContain('🔴 Critical: **1**');
    expect(md).toContain('🟠 High: **1**');
  });

  it('renders detailed finding cards with code snippet and remediation', () => {
    const md = generateMarkdownReport(sampleReport);

    expect(md).toContain('payment/payment-amount-tampering');
    expect(md).toContain('stripe.charges.create({ amount: req.body.amount })');
    expect(md).toContain('Lookup product prices on the server');
    expect(md).toContain('auth/missing-auth-middleware');
    expect(md).toContain('Attach requireAuth middleware');
  });

  it('renders correlated attack chains when present', () => {
    const md = generateMarkdownReport(sampleReport);

    expect(md).toContain('Correlated Attack Chains');
    expect(md).toContain('Tampered Checkout to Privilege Escalation');
    expect(md).toContain('An attacker modifies price during checkout');
  });

  it('handles clean scan with 0 findings gracefully', () => {
    const cleanReport = {
      scannerVersion: '1.0.0',
      scanDate: '2026-10-07T12:00:00.000Z',
      targetDirectory: '/projects/clean',
      summary: {
        totalFiles: 10,
        totalFindings: 0,
        severities: { critical: 0, high: 0, medium: 0, low: 0 },
        scanDurationMs: 85
      },
      findings: []
    };

    const md = generateMarkdownReport(cleanReport);

    expect(md).toContain('Clean Scan — No Vulnerabilities Detected');
    expect(md).toContain('All automated static analysis checks passed');
    expect(md).not.toContain('Findings Overview');
  });

  it('handles null or empty report without throwing', () => {
    expect(() => generateMarkdownReport(null)).not.toThrow();
    const result = generateMarkdownReport(null);
    expect(result).toContain('No scan report data available');
  });

  it('escapes pipe characters in finding message to prevent GFM table corruption', () => {
    const reportWithPipes = {
      summary: { totalFiles: 1, totalFindings: 1, severities: { critical: 1, high: 0, medium: 0, low: 0 } },
      findings: [
        {
          ruleId: 'injection/sql-injection',
          severity: 'critical',
          file: 'routes/search.js',
          line: 5,
          message: 'Vulnerable query: SELECT * FROM users WHERE a = 1 | b = 2'
        }
      ]
    };

    const md = generateMarkdownReport(reportWithPipes);
    expect(md).toContain('SELECT * FROM users WHERE a = 1 \\| b = 2');
  });

  it('handles pre-fenced remediation and code snippets with backticks without double-fencing', () => {
    const reportWithFences = {
      summary: { totalFiles: 1, totalFindings: 1, severities: { critical: 1, high: 0, medium: 0, low: 0 } },
      findings: [
        {
          ruleId: 'payment/amount',
          severity: 'critical',
          file: 'checkout.js',
          line: 12,
          codeSnippet: '```db.query(`SELECT price`)```',
          remediation: '```javascript\nconst price = await db.getPrice();\n```'
        }
      ]
    };

    const md = generateMarkdownReport(reportWithFences);
    // Should not produce invalid nested code blocks like ```javascript\n```javascript
    expect(md).not.toContain('```javascript\n```javascript');
    expect(md).toContain('````javascript\n```db.query(`SELECT price`)```\n````');
  });

  it('handles findings with missing line, column, and uppercase severity gracefully', () => {
    const reportMissingFields = {
      summary: { totalFiles: 1, totalFindings: 1, severities: { critical: 1, high: 0, medium: 0, low: 0 } },
      findings: [
        {
          ruleId: 'secrets/hardcoded-secrets',
          severity: 'CRITICAL',
          file: 'config.js'
        }
      ]
    };

    const md = generateMarkdownReport(reportMissingFields);
    expect(md).not.toContain(':undefined');
    expect(md).toContain('CRITICAL');
  });

  it('renders explicit AI Analysis Engine provenance badge for online and offline modes', () => {
    const onlineReport = {
      summary: { totalFiles: 2, totalFindings: 1, severities: { critical: 1, high: 0, medium: 0, low: 0 } },
      aiMode: 'online',
      aiEngine: 'Google Gemini 3.8 Flash',
      findings: [
        {
          ruleId: 'payment/amount',
          severity: 'critical',
          file: 'checkout.js',
          line: 10,
          aiMode: 'online',
          aiEngine: 'Google Gemini 3.8 Flash'
        }
      ]
    };

    const onlineMd = generateMarkdownReport(onlineReport);
    expect(onlineMd).toContain('**AI Analysis Engine**');
    expect(onlineMd).toContain('🌐 Online (Google Gemini 3.8 Flash');
    expect(onlineMd).toContain('- **AI Provenance**: `🌐 Online — Google Gemini 3.8 Flash`');

    const offlineReport = {
      summary: { totalFiles: 2, totalFindings: 1, severities: { critical: 0, high: 1, medium: 0, low: 0 } },
      aiMode: 'offline',
      aiEngine: 'Deterministic Heuristics',
      findings: [
        {
          ruleId: 'crypto/weak',
          severity: 'high',
          file: 'token.js',
          line: 4,
          aiMode: 'offline'
        }
      ]
    };

    const offlineMd = generateMarkdownReport(offlineReport);
    expect(offlineMd).toContain('**AI Analysis Engine**');
    expect(offlineMd).toContain('🔌 Offline (Deterministic Heuristics');
    expect(offlineMd).toContain('- **AI Provenance**: `🔌 Offline — Local Heuristic`');
  });
});

