import { describe, it, expect } from 'vitest';
import path from 'node:path';
import trustlayerDefault, {
  scan,
  scanFile,
  discoverFiles,
  parseSource,
  loadRules,
  rules,
  enhanceReport,
  generateMarkdownReport,
  generateJsonReport,
  toSarif,
  SCANNER_VERSION,
  VALID_SEVERITIES,
  VALID_CATEGORIES
} from '../../src/index.js';

describe('Programmatic Library API (src/index.js)', () => {
  const demoPath = path.resolve(process.cwd(), 'demo');

  it('exports all expected core primitives as named exports', () => {
    expect(typeof scan).toBe('function');
    expect(typeof scanFile).toBe('function');
    expect(typeof discoverFiles).toBe('function');
    expect(typeof parseSource).toBe('function');
    expect(typeof loadRules).toBe('function');
    expect(Array.isArray(rules)).toBe(true);
    expect(typeof enhanceReport).toBe('function');
    expect(typeof generateMarkdownReport).toBe('function');
    expect(typeof generateJsonReport).toBe('function');
    expect(typeof toSarif).toBe('function');
    expect(typeof SCANNER_VERSION).toBe('string');
    expect(VALID_SEVERITIES).toEqual(['critical', 'high', 'medium', 'low']);
    expect(VALID_CATEGORIES).toEqual(['secrets', 'injection', 'payment', 'auth']);
  });

  it('provides a default export object mirroring named exports', () => {
    expect(trustlayerDefault).toBeDefined();
    expect(trustlayerDefault.scan).toBe(scan);
    expect(trustlayerDefault.scanFile).toBe(scanFile);
    expect(trustlayerDefault.discoverFiles).toBe(discoverFiles);
    expect(trustlayerDefault.parseSource).toBe(parseSource);
    expect(trustlayerDefault.loadRules).toBe(loadRules);
    expect(trustlayerDefault.rules).toBe(rules);
    expect(trustlayerDefault.enhanceReport).toBe(enhanceReport);
    expect(trustlayerDefault.generateMarkdownReport).toBe(generateMarkdownReport);
    expect(trustlayerDefault.generateJsonReport).toBe(generateJsonReport);
    expect(trustlayerDefault.toSarif).toBe(toSarif);
    expect(trustlayerDefault.SCANNER_VERSION).toBe(SCANNER_VERSION);
  });

  it('pre-loads built-in security rules in the exported rules array', () => {
    expect(rules.length).toBeGreaterThanOrEqual(7);
    const ruleIds = rules.map(r => r.id);
    expect(ruleIds).toContain('payment/payment-amount-tampering');
    expect(ruleIds).toContain('payment/missing-webhook-verification');
    expect(ruleIds).toContain('auth/missing-auth-middleware');
    expect(ruleIds).toContain('injection/sql-injection');
    expect(ruleIds).toContain('secrets/hardcoded-secrets');
  });

  it('programmatically scans a directory and returns a structured ScanReport', async () => {
    const report = await scan(demoPath);

    expect(report).toBeDefined();
    expect(report.scannerVersion).toBe(SCANNER_VERSION);
    expect(report.targetDirectory).toBe(demoPath);
    expect(report.summary).toBeDefined();
    expect(report.summary.totalFiles).toBeGreaterThan(0);
    expect(report.summary.totalFindings).toBeGreaterThan(0);
    expect(report.summary.severities).toBeDefined();
    expect(typeof report.summary.scanDurationMs).toBe('number');
    expect(Array.isArray(report.findings)).toBe(true);
    expect(report.findings.length).toBe(report.summary.totalFindings);
  });

  it('supports programmatic severity filtering', async () => {
    const criticalReport = await scan(demoPath, { severity: ['critical'] });

    expect(criticalReport.findings.length).toBeGreaterThan(0);
    for (const finding of criticalReport.findings) {
      expect(finding.severity.toLowerCase()).toBe('critical');
    }
  });

  it('supports programmatic category filtering', async () => {
    const paymentReport = await scan(demoPath, { category: ['payment'] });

    expect(paymentReport.findings.length).toBeGreaterThan(0);
    for (const finding of paymentReport.findings) {
      const category = finding.category || finding.ruleId.split('/')[0];
      expect(category.toLowerCase()).toBe('payment');
    }
  });

  it('supports injecting custom rules into programmatic scan', async () => {
    const customRule = {
      id: 'custom/test-marker',
      name: 'Custom Test Marker',
      severity: 'low',
      category: 'secrets',
      description: 'Finds custom markers',
      defaultExplanation: 'Custom explanation',
      defaultRemediation: 'Custom remediation',
      analyze(context) {
        return [{
          ruleId: 'custom/test-marker',
          severity: 'low',
          category: 'secrets',
          line: 1,
          message: 'Found marker'
        }];
      }
    };

    const report = await scan(demoPath, { rules: [customRule] });
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.every(f => f.ruleId === 'custom/test-marker')).toBe(true);
  });

  it('allows programmatic file discovery and source parsing', async () => {
    const discovered = await discoverFiles(demoPath);
    expect(Array.isArray(discovered)).toBe(true);
    expect(discovered.length).toBeGreaterThan(0);

    const code = 'const apiKey = "sk_test_12345";';
    const parsed = parseSource(code, 'virtual-test.js');
    expect(parsed).toBeDefined();
    expect(parsed.ast).toBeDefined();
    expect(parsed.ast.type).toBe('File');
  });

  it('integrates seamlessly with reporters and AI enhancer', async () => {
    const report = await scan(demoPath);

    // Markdown Reporter
    const md = generateMarkdownReport(report);
    expect(typeof md).toBe('string');
    expect(md).toContain('# 🛡️ TrustLayer Security Audit Report');

    // JSON Reporter
    const jsonStr = generateJsonReport(report);
    const parsedJson = JSON.parse(jsonStr);
    expect(parsedJson.summary).toBeDefined();

    // SARIF Exporter
    const sarifDoc = toSarif(report);
    expect(sarifDoc.version).toBe('2.1.0');
    expect(sarifDoc.runs).toHaveLength(1);

    // AI Enhancer (Deterministic offline fallback)
    const enhanced = await enhanceReport(report, { offline: true });
    expect(enhanced).toBeDefined();
    expect(enhanced.attackChains).toBeDefined();
  });
});
