import { describe, it, expect } from 'vitest';
import { generateJsonReport, toSarif } from '../../src/reporters/json-reporter.js';

describe('Reporter: json-reporter', () => {
  const sampleReport = {
    scannerVersion: '1.0.0',
    scanDate: '2026-10-07T12:00:00.000Z',
    targetDirectory: '/projects/quickshop',
    summary: {
      totalFiles: 1,
      totalFindings: 1,
      severities: { critical: 1, high: 0, medium: 0, low: 0 },
      scanDurationMs: 50
    },
    findings: [
      {
        ruleId: 'payment/payment-amount-tampering',
        severity: 'critical',
        file: '/projects/quickshop/routes/checkout.js',
        line: 18,
        column: 7,
        codeSnippet: 'stripe.charges.create({ amount: req.body.amount });',
        message: 'Client-controlled payment amount detected',
        confidence: 'high'
      }
    ]
  };

  it('serializes valid report to JSON string', () => {
    const jsonStr = generateJsonReport(sampleReport);
    const parsed = JSON.parse(jsonStr);

    expect(parsed.scannerVersion).toBe('1.0.0');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].ruleId).toBe('payment/payment-amount-tampering');
  });

  it('supports compact JSON when pretty is false', () => {
    const jsonStr = generateJsonReport(sampleReport, { pretty: false });
    expect(jsonStr).not.toContain('\n  "scannerVersion"');
  });

  it('converts report to standard SARIF 2.1.0 document', () => {
    const sarif = toSarif(sampleReport);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('TrustLayer');
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('payment/payment-amount-tampering');
    expect(sarif.runs[0].results[0].level).toBe('error');
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(18);
  });

  it('handles empty or null report safely', () => {
    const emptyJson = generateJsonReport(null);
    expect(JSON.parse(emptyJson)).toHaveProperty('error');

    const emptySarif = toSarif(null);
    expect(emptySarif.version).toBe('2.1.0');
    expect(emptySarif.runs[0].results).toEqual([]);
  });

  it('normalizes Windows backslash filepaths to forward slashes in SARIF URIs', () => {
    const reportWindowsPaths = {
      findings: [
        {
          ruleId: 'injection/sql-injection',
          severity: 'high',
          file: 'demo\\routes\\products.js',
          line: 10
        }
      ]
    };

    const sarif = toSarif(reportWindowsPaths);
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('demo/routes/products.js');
  });

  it('maps all severities correctly to SARIF level equivalents and enriches rule definitions', () => {
    const multiSevReport = {
      findings: [
        { ruleId: 'rule/crit', severity: 'critical', file: 'a.js', line: 1, message: 'Crit msg', remediation: 'Fix crit' },
        { ruleId: 'rule/high', severity: 'high', file: 'b.js', line: 2 },
        { ruleId: 'rule/med', severity: 'medium', file: 'c.js', line: 3 },
        { ruleId: 'rule/low', severity: 'low', file: 'd.js', line: 4 }
      ]
    };

    const sarif = toSarif(multiSevReport);
    const results = sarif.runs[0].results;

    expect(results[0].level).toBe('error');
    expect(results[1].level).toBe('error');
    expect(results[2].level).toBe('warning');
    expect(results[3].level).toBe('note');

    const rule = sarif.runs[0].tool.driver.rules.find(r => r.id === 'rule/crit');
    expect(rule.shortDescription.text).toBe('Crit msg');
    expect(rule.help.text).toBe('Fix crit');
  });
});
