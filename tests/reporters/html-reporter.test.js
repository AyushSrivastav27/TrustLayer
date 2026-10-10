import { describe, it, expect } from 'vitest';
import { generateHtmlReport, escapeHtml } from '../../src/reporters/html-reporter.js';

describe('Reporter: html-reporter', () => {
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

  it('renders report header, target, and executive summary metrics', () => {
    const html = generateHtmlReport(sampleReport);

    expect(html).toContain('TrustLayer Security Audit Report');
    expect(html).toContain('/projects/quickshop');
    expect(html).toContain('140ms');
    expect(html).toContain('5');
    expect(html).toContain('2');
    expect(html).toContain('Critical: <strong>1</strong>');
    expect(html).toContain('High: <strong>1</strong>');
  });

  it('renders detailed finding cards with code snippet and remediation', () => {
    const html = generateHtmlReport(sampleReport);

    expect(html).toContain('payment/payment-amount-tampering');
    expect(html).toContain('stripe.charges.create({ amount: req.body.amount });');
    expect(html).toContain('Lookup product prices on the server');
    expect(html).toContain('auth/missing-auth-middleware');
    expect(html).toContain('Attach requireAuth middleware');
    expect(html).toContain('routes/checkout.js:18:7');
  });

  it('renders correlated attack chains when present', () => {
    const html = generateHtmlReport(sampleReport);

    expect(html).toContain('Correlated Attack Chains (1)');
    expect(html).toContain('Tampered Checkout to Privilege Escalation');
    expect(html).toContain('An attacker modifies price during checkout and accesses order records.');
    expect(html).toContain('Participating Rules:');
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

    const html = generateHtmlReport(cleanReport);

    expect(html).toContain('100% Clean Scan — Zero Flaws Detected');
    expect(html).toContain('All automated static security checks passed');
    expect(html).not.toContain('id="findingsContainer"');
  });

  it('handles null or empty report without throwing', () => {
    expect(() => generateHtmlReport(null)).not.toThrow();
    const result = generateHtmlReport(null);
    expect(result).toContain('No scan report data available');
  });

  it('safely escapes HTML in messages, rules, and code snippets', () => {
    const reportWithMaliciousContent = {
      summary: { totalFiles: 1, totalFindings: 1, severities: { critical: 1, high: 0, medium: 0, low: 0 } },
      findings: [
        {
          ruleId: 'injection/xss<script>',
          severity: 'critical',
          file: 'routes/<script>alert("xss")</script>.js',
          line: 5,
          message: 'Vulnerable: <b>bold</b> & "quotes"',
          codeSnippet: '<script>alert(1)</script>'
        }
      ]
    };

    const html = generateHtmlReport(reportWithMaliciousContent);
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&lt;b&gt;bold&lt;/b&gt; &amp; &quot;quotes&quot;');
  });

  it('escapeHtml helper handles null, undefined, and special characters', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
    expect(escapeHtml('a & b < c > d "e" \'f\'')).toBe('a &amp; b &lt; c &gt; d &quot;e&quot; &#039;f&#039;');
  });

  it('renders AI provenance badge for online and offline modes', () => {
    const onlineReport = {
      summary: { totalFiles: 1, totalFindings: 1, severities: { critical: 1, high: 0, medium: 0, low: 0 } },
      aiMode: 'online',
      aiEngine: 'Google Gemini 3.8 Flash',
      findings: [
        {
          ruleId: 'payment/amount',
          severity: 'critical',
          file: 'checkout.js',
          line: 10,
          aiMode: 'online'
        }
      ]
    };

    const onlineHtml = generateHtmlReport(onlineReport);
    expect(onlineHtml).toContain('badge-online');
    expect(onlineHtml).toContain('Google Gemini 3.8 Flash');

    const offlineReport = {
      summary: { totalFiles: 1, totalFindings: 1, severities: { critical: 0, high: 1, medium: 0, low: 0 } },
      aiMode: 'offline',
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

    const offlineHtml = generateHtmlReport(offlineReport);
    expect(offlineHtml).toContain('badge-offline');
    expect(offlineHtml).toContain('Air-Gapped');
  });

  it('renders interactive filter buttons and search input', () => {
    const html = generateHtmlReport(sampleReport);
    expect(html).toContain('class="filter-btn active" data-filter="all"');
    expect(html).toContain('data-filter="critical"');
    expect(html).toContain('id="searchInput"');
    expect(html).toContain('copyCode(this)');
  });
});
