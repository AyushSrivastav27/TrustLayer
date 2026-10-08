import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverFiles } from './file-discovery.js';
import { parseSource } from './ast-parser.js';
import { loadRules } from './rule-registry.js';
import { calculateSeverityCounts } from '../types/report.js';

let packageVersion = '1.0.0';
try {
  const pkgPath = fileURLToPath(new URL('../../package.json', import.meta.url));
  const pkg = JSON.parse(fsSync.readFileSync(pkgPath, 'utf-8'));
  if (pkg && pkg.version) {
    packageVersion = pkg.version;
  }
} catch {
  // fallback if package.json cannot be read
}

export const SCANNER_VERSION = packageVersion;

/**
 * Scans a single file against an array of rules.
 *
 * @param {string} filePath - Path to file
 * @param {import('../types/rule.js').Rule[]} rules - Rules to run
 * @param {string} [content] - Optional pre-read file content
 * @returns {Promise<import('../types/finding.js').Finding[]>}
 */
export async function scanFile(filePath, rules, content = null) {
  const fileContent = content !== null ? content : await fs.readFile(filePath, 'utf-8');
  const lines = fileContent.split(/\r?\n/);
  const { ast } = parseSource(fileContent, filePath);

  /** @type {import('../types/rule.js').AnalysisContext} */
  const context = {
    filePath,
    fileContent,
    ast,
    lines
  };

  const perRulePromises = rules.map(async (rule) => {
    try {
      const result = await rule.analyze(context);
      const findings = Array.isArray(result) ? result : [];

      return findings.map((finding) => ({
        ruleId: finding.ruleId || rule.id,
        severity: finding.severity || rule.severity,
        file: finding.file || filePath,
        line: finding.line,
        endLine: finding.endLine,
        column: finding.column,
        codeSnippet: finding.codeSnippet || (finding.line ? lines[finding.line - 1] || '' : ''),
        message: finding.message || rule.description,
        explanation: finding.explanation || rule.defaultExplanation,
        remediation: finding.remediation || rule.defaultRemediation,
        confidence: finding.confidence || 'high'
      }));
    } catch (err) {
      console.warn(`[TrustLayer] Error executing rule "${rule.id}" on "${filePath}":`, err.message);
      return [];
    }
  });

  const perRuleFindings = await Promise.all(perRulePromises);
  return perRuleFindings.flat();
}

/**
 * Main scanner entry point.
 * Scans a target path and returns a structured ScanReport.
 *
 * @param {string} targetPath - Directory or single file path to scan
 * @param {Object} [options]
 * @param {import('../types/rule.js').Rule[]} [options.rules] - Optional preloaded rules
 * @param {string} [options.rulesDir] - Custom directory to load rules from
 * @param {string[]} [options.ignore] - Additional glob ignore patterns
 * @param {(progress: { current: number, total: number, file: string, findingsCount: number }) => void} [options.onProgress]
 * @returns {Promise<import('../types/report.js').ScanReport>}
 */
export async function scan(targetPath, options = {}) {
  const startTime = Date.now();
  const resolvedTarget = path.resolve(targetPath);

  const rules = options.rules || await loadRules(options.rulesDir);
  const files = await discoverFiles(resolvedTarget, { ignore: options.ignore });

  const allFindings = [];

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const findings = await scanFile(file, rules);
    allFindings.push(...findings);

    if (typeof options.onProgress === 'function') {
      options.onProgress({
        current: i + 1,
        total: files.length,
        file,
        findingsCount: allFindings.length
      });
    }
  }

  const durationMs = Date.now() - startTime;
  const severities = calculateSeverityCounts(allFindings);

  return {
    scannerVersion: SCANNER_VERSION,
    scanDate: new Date().toISOString(),
    targetDirectory: resolvedTarget,
    summary: {
      totalFiles: files.length,
      totalFindings: allFindings.length,
      severities,
      scanDurationMs: durationMs
    },
    findings: allFindings
  };
}
