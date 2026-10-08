import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverFiles } from './file-discovery.js';
import { parseSource } from './ast-parser.js';
import { loadRules } from './rule-registry.js';
import { calculateSeverityCounts } from '../types/report.js';
import { createFinding } from '../types/finding.js';

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
 * Checks if a finding is suppressed by inline comments in the source code.
 * Supports:
 *   // trustlayer-disable-next-line [ruleId]
 *   // trustlayer-disable-line [ruleId]
 *   // trustlayer-ignore [ruleId]
 *
 * @param {import('../types/finding.js').Finding} finding
 * @param {string[]} lines
 * @returns {boolean}
 */
export function isFindingSuppressed(finding, lines) {
  if (!finding.line || finding.line < 1 || !Array.isArray(lines) || finding.line > lines.length) {
    return false;
  }

  const currentLineIndex = finding.line - 1;
  const prevLineIndex = currentLineIndex - 1;

  function ruleMatches(ruleQuery, targetRuleId) {
    if (!ruleQuery) return true;
    const tokens = ruleQuery.trim().split(/[\s,]+/).filter(Boolean);
    if (tokens.length === 0) return true;
    return tokens.some((token) => {
      const cleanToken = token.toLowerCase();
      const cleanTarget = targetRuleId.toLowerCase();
      return cleanTarget === cleanToken ||
             cleanTarget.endsWith(`/${cleanToken}`) ||
             cleanTarget.includes(cleanToken);
    });
  }

  // 1. Check previous line for disable-next-line
  if (prevLineIndex >= 0) {
    const prevLine = lines[prevLineIndex] || '';
    const match = prevLine.match(/(?:\/\/|\/\*|\*)\s*trustlayer-(?:disable-next-line|ignore-next-line)(?:\s+([^\*\/]+))?/i);
    if (match && ruleMatches(match[1], finding.ruleId)) {
      return true;
    }
  }

  // 2. Check current line for disable-line or ignore
  const currentLine = lines[currentLineIndex] || '';
  const matchCurrent = currentLine.match(/(?:\/\/|\/\*|\*)\s*trustlayer-(?:disable-line|ignore)(?:\s+([^\*\/]+))?/i);
  if (matchCurrent && ruleMatches(matchCurrent[1], finding.ruleId)) {
    return true;
  }

  return false;
}

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

      return findings.map((finding) =>
        createFinding({
          ruleId: finding.ruleId || rule.id,
          severity: finding.severity || rule.severity,
          category: finding.category || rule.category,
          file: finding.file || filePath,
          line: typeof finding.line === 'number' ? finding.line : 1,
          endLine: finding.endLine,
          column: finding.column,
          codeSnippet: finding.codeSnippet || (finding.line ? lines[finding.line - 1] || '' : ''),
          message: finding.message || rule.description,
          explanation: finding.explanation || rule.defaultExplanation,
          remediation: finding.remediation || rule.defaultRemediation,
          confidence: finding.confidence || 'high'
        })
      );
    } catch (err) {
      console.warn(`[TrustLayer] Error executing rule "${rule.id}" on "${filePath}":`, err.message);
      return [];
    }
  });

  const perRuleFindings = await Promise.all(perRulePromises);
  const rawFindings = perRuleFindings.flat();
  return rawFindings.filter((finding) => !isFindingSuppressed(finding, lines));
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
  const files = options.files
    ? options.files.map((f) => path.resolve(f))
    : await discoverFiles(resolvedTarget, { ignore: options.ignore });

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

  let finalFindings = allFindings;
  if (Array.isArray(options.severity) && options.severity.length > 0) {
    const allowed = options.severity.map((s) => s.toLowerCase());
    finalFindings = finalFindings.filter((f) => allowed.includes((f.severity || '').toLowerCase()));
  }
  if (Array.isArray(options.category) && options.category.length > 0) {
    const allowed = options.category.map((c) => c.toLowerCase());
    finalFindings = finalFindings.filter((f) => {
      const cat = f.category || (f.ruleId || '').split('/')[0] || '';
      return allowed.includes(cat.toLowerCase());
    });
  }

  const durationMs = Date.now() - startTime;
  const severities = calculateSeverityCounts(finalFindings);

  return {
    scannerVersion: SCANNER_VERSION,
    scanDate: new Date().toISOString(),
    targetDirectory: resolvedTarget,
    summary: {
      totalFiles: files.length,
      totalFindings: finalFindings.length,
      severities,
      scanDurationMs: durationMs
    },
    findings: finalFindings
  };
}
