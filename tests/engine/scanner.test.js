import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { scanFile, scan, SCANNER_VERSION } from '../../src/engine/scanner.js';

describe('Engine: scanner', () => {
  let tempScanDir;
  let sampleFilePath;

  // Mock rules
  const mockVulnerableRule = {
    id: 'test/vulnerable-keyword',
    name: 'Vulnerable Keyword Rule',
    severity: 'critical',
    category: 'injection',
    description: 'Flags dangerous tokens',
    defaultExplanation: 'Default explanation text',
    defaultRemediation: 'Default remediation text',
    analyze(context) {
      const findings = [];
      context.lines.forEach((line, index) => {
        if (line.includes('DANGEROUS_CALL')) {
          findings.push({
            line: index + 1,
            column: 1,
            message: 'Dangerous call found'
          });
        }
      });
      return findings;
    }
  };

  const mockCrashingRule = {
    id: 'test/crashing-rule',
    name: 'Broken Rule',
    severity: 'medium',
    category: 'auth',
    description: 'Always throws',
    defaultExplanation: 'None',
    defaultRemediation: 'None',
    analyze() {
      throw new Error('Intentional AST rule crash');
    }
  };

  const mockCleanRule = {
    id: 'test/clean-rule',
    name: 'Clean Rule',
    severity: 'low',
    category: 'secrets',
    description: 'Flags nothing',
    defaultExplanation: 'None',
    defaultRemediation: 'None',
    analyze() {
      return [];
    }
  };

  beforeAll(async () => {
    tempScanDir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustlayer-scanner-'));

    sampleFilePath = path.join(tempScanDir, 'sample.js');
    const sampleCode = [
      '// Line 1: Header',
      'const clean = 123;',
      'const bad = DANGEROUS_CALL();',
      'console.log(clean);'
    ].join('\n');

    await fs.writeFile(sampleFilePath, sampleCode);

    // Clean file
    await fs.writeFile(path.join(tempScanDir, 'clean.js'), 'const a = 1;\nconsole.log(a);');
  });

  afterAll(async () => {
    if (tempScanDir) {
      await fs.rm(tempScanDir, { recursive: true, force: true });
    }
  });

  describe('scanFile', () => {
    it('scans a file and extracts findings with applied default fallbacks', async () => {
      const findings = await scanFile(sampleFilePath, [mockVulnerableRule]);

      expect(findings).toHaveLength(1);
      const finding = findings[0];

      expect(finding.ruleId).toBe('test/vulnerable-keyword');
      expect(finding.severity).toBe('critical');
      expect(finding.file).toBe(sampleFilePath);
      expect(finding.line).toBe(3);
      expect(finding.codeSnippet).toBe('const bad = DANGEROUS_CALL();');
      expect(finding.message).toBe('Dangerous call found');
      expect(finding.explanation).toBe('Default explanation text');
      expect(finding.remediation).toBe('Default remediation text');
      expect(finding.confidence).toBe('high');
    });

    it('uses pre-read content argument when supplied', async () => {
      const customContent = 'const custom = DANGEROUS_CALL();';
      const findings = await scanFile(sampleFilePath, [mockVulnerableRule], customContent);

      expect(findings).toHaveLength(1);
      expect(findings[0].line).toBe(1);
      expect(findings[0].codeSnippet).toBe('const custom = DANGEROUS_CALL();');
    });

    it('returns empty array when no rules flag anything', async () => {
      const cleanFilePath = path.join(tempScanDir, 'clean.js');
      const findings = await scanFile(cleanFilePath, [mockCleanRule]);

      expect(findings).toEqual([]);
    });

    it('gracefully handles and isolates throwing rules without halting execution', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      // Running both crashing and vulnerable rules
      const findings = await scanFile(sampleFilePath, [mockCrashingRule, mockVulnerableRule]);

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Error executing rule "test/crashing-rule"'),
        expect.any(String)
      );
      // The vulnerable rule still succeeded
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('test/vulnerable-keyword');

      warnSpy.mockRestore();
    });

    it('executes multiple rules concurrently and flattens all findings', async () => {
      const asyncRule1 = {
        id: 'test/async-1',
        severity: 'high',
        analyze: async () => [{ line: 1, message: 'Async 1 finding' }]
      };
      const asyncRule2 = {
        id: 'test/async-2',
        severity: 'medium',
        analyze: async () => [{ line: 2, message: 'Async 2 finding' }]
      };

      const findings = await scanFile(sampleFilePath, [asyncRule1, asyncRule2, mockVulnerableRule]);
      expect(findings).toHaveLength(3);
      const ruleIds = findings.map(f => f.ruleId);
      expect(ruleIds).toContain('test/async-1');
      expect(ruleIds).toContain('test/async-2');
      expect(ruleIds).toContain('test/vulnerable-keyword');
    });
  });

  describe('scan', () => {
    it('orchestrates end-to-end directory scanning and produces a valid ScanReport', async () => {
      const report = await scan(tempScanDir, {
        rules: [mockVulnerableRule, mockCleanRule]
      });

      expect(report.scannerVersion).toBe(SCANNER_VERSION);
      expect(report.scannerVersion).toBe('1.0.0');
      expect(report.scanDate).toBeDefined();
      expect(new Date(report.scanDate).toString()).not.toBe('Invalid Date');
      expect(report.targetDirectory).toBe(path.resolve(tempScanDir));

      // Summary checks
      expect(report.summary.totalFiles).toBe(2);
      expect(report.summary.totalFindings).toBe(1);
      expect(report.summary.scanDurationMs).toBeGreaterThanOrEqual(0);
      expect(report.summary.severities).toEqual({
        critical: 1,
        high: 0,
        medium: 0,
        low: 0
      });

      // Findings checks
      expect(report.findings).toHaveLength(1);
      expect(report.findings[0].ruleId).toBe('test/vulnerable-keyword');
    });

    it('invokes onProgress callback for each scanned file', async () => {
      const progressCalls = [];
      const onProgress = vi.fn((progress) => {
        progressCalls.push({ ...progress });
      });

      await scan(tempScanDir, {
        rules: [mockVulnerableRule],
        onProgress
      });

      expect(onProgress).toHaveBeenCalledTimes(2);
      expect(progressCalls[0].current).toBe(1);
      expect(progressCalls[0].total).toBe(2);
      expect(progressCalls[1].current).toBe(2);
      expect(progressCalls[1].total).toBe(2);
      expect(progressCalls[1].findingsCount).toBe(1);
    });

    it('respects options.ignore to exclude specific files', async () => {
      const report = await scan(tempScanDir, {
        rules: [mockVulnerableRule],
        ignore: ['**/sample.js']
      });

      // Only clean.js scanned
      expect(report.summary.totalFiles).toBe(1);
      expect(report.summary.totalFindings).toBe(0);
      expect(report.findings).toEqual([]);
    });
  });
});
