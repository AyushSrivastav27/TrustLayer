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

  it('includes endColumn in SARIF region when provided on findings', () => {
    const reportWithEndCol = {
      findings: [
        {
          ruleId: 'secrets/hardcoded-secrets',
          severity: 'critical',
          file: 'config.js',
          line: 5,
          column: 10,
          endLine: 5,
          endColumn: 35
        }
      ]
    };

    const sarif = toSarif(reportWithEndCol);
    const region = sarif.runs[0].results[0].locations[0].physicalLocation.region;
    expect(region.startLine).toBe(5);
    expect(region.startColumn).toBe(10);
    expect(region.endLine).toBe(5);
    expect(region.endColumn).toBe(35);
  });
});

describe('M5-4 Verification: SARIF v2.1.0 endColumn & Worst-Case Scenario Tests', () => {
  it('contradiction test: endColumn is strictly preserved when provided as a positive integer', () => {
    const report = {
      findings: [
        {
          ruleId: 'payment/payment-amount-tampering',
          severity: 'critical',
          file: 'checkout.js',
          line: 12,
          column: 5,
          endLine: 12,
          endColumn: 48
        }
      ]
    };

    const sarif = toSarif(report);
    const region = sarif.runs[0].results[0].locations[0].physicalLocation.region;

    // Contradiction assertion: endColumn must match 48 exactly
    expect(region).toHaveProperty('endColumn', 48);
  });

  it('contradiction test: endColumn is omitted when not provided or non-numeric', () => {
    const reportWithout = {
      findings: [
        {
          ruleId: 'injection/sql-injection',
          severity: 'high',
          file: 'routes/products.js',
          line: 25,
          column: 1
        },
        {
          ruleId: 'auth/missing-auth-middleware',
          severity: 'medium',
          file: 'routes/orders.js',
          line: 10,
          endColumn: 'invalid_string'
        },
        {
          ruleId: 'secrets/hardcoded-secrets',
          severity: 'critical',
          file: 'routes/auth.js',
          line: 8,
          endColumn: null
        }
      ]
    };

    const sarif = toSarif(reportWithout);
    const results = sarif.runs[0].results;

    // Contradiction assertion: Must not leak undefined/null/invalid into serialized SARIF
    expect(results[0].locations[0].physicalLocation.region.endColumn).toBeUndefined();
    expect(results[1].locations[0].physicalLocation.region.endColumn).toBeUndefined();
    expect(results[2].locations[0].physicalLocation.region.endColumn).toBeUndefined();

    // Verify valid JSON serialization
    const serialized = JSON.stringify(sarif);
    expect(serialized).not.toContain('"endColumn":null');
    expect(serialized).not.toContain('"endColumn":"invalid_string"');
  });

  it('worst-case scenario: sparse and corrupted findings array does not crash toSarif', () => {
    const adversarialReport = {
      scannerVersion: '1.0.0',
      findings: [
        null,
        undefined,
        'not-an-object',
        12345,
        {},
        { ruleId: 'valid/rule', severity: 'HIGH', file: 'ok.js', line: 10, endColumn: 20 }
      ]
    };

    expect(() => {
      const sarif = toSarif(adversarialReport);
      expect(sarif.runs[0].results).toHaveLength(2); // The empty object and the valid rule
      expect(sarif.runs[0].results[1].ruleId).toBe('valid/rule');
      expect(sarif.runs[0].results[1].level).toBe('error');
      expect(sarif.runs[0].results[1].locations[0].physicalLocation.region.endColumn).toBe(20);
    }).not.toThrow();
  });

  it('worst-case scenario: non-array findings and null options handled gracefully', () => {
    expect(() => {
      const sarif = toSarif({ findings: 'invalid-findings-type' });
      expect(sarif.runs[0].results).toEqual([]);
    }).not.toThrow();

    expect(() => {
      const json = generateJsonReport({ scannerVersion: '1.0.0' }, null);
      expect(JSON.parse(json)).toHaveProperty('scannerVersion', '1.0.0');
    }).not.toThrow();
  });

  it('worst-case scenario: cyclic reference in report is caught without process termination', () => {
    const cyclicReport = { scannerVersion: '1.0.0' };
    cyclicReport.self = cyclicReport;

    const result = generateJsonReport(cyclicReport);
    const parsed = JSON.parse(result);

    expect(parsed).toHaveProperty('error', 'Serialization failed');
    expect(parsed).toHaveProperty('message');
  });
});

