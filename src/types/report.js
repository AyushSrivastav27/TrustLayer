/**
 * @typedef {import('./finding.js').Finding} Finding
 */

/**
 * Breakdown of finding counts by severity.
 * @typedef {Object} SeverityCounts
 * @property {number} critical - Number of critical severity findings
 * @property {number} high - Number of high severity findings
 * @property {number} medium - Number of medium severity findings
 * @property {number} low - Number of low severity findings
 */

/**
 * Summary metrics of a completed security scan.
 * @typedef {Object} ScanSummary
 * @property {number} totalFiles - Total number of files scanned
 * @property {number} totalFindings - Total vulnerability findings detected
 * @property {SeverityCounts} severities - Count breakdown by severity
 * @property {number} scanDurationMs - Scan execution time in milliseconds
 */

/**
 * Correlated multi-step vulnerability sequence (AI-enhanced).
 * @typedef {Object} AttackChain
 * @property {string} title - Chain title (e.g. 'Unauthenticated Admin Impersonation to DB Exfiltration')
 * @property {string} description - Step-by-step description of combined exploitability
 * @property {string[]} findingIds - Rule IDs participating in this attack chain
 * @property {'critical' | 'high'} severity - Combined risk rating
 */

/**
 * The complete output payload of a TrustLayer scan.
 * @typedef {Object} ScanReport
 * @property {string} scannerVersion - TrustLayer version (e.g. '1.0.0')
 * @property {string} scanDate - ISO 8601 timestamp of scan completion
 * @property {string} targetDirectory - Path to the directory scanned
 * @property {ScanSummary} summary - Aggregated scan statistics
 * @property {Finding[]} findings - List of individual vulnerability findings
 * @property {AttackChain[]} [attackChains] - Correlated exploit chains if AI enabled
 */

/**
 * Helper to compute severity counts from a list of findings.
 *
 * @param {Finding[]} findings
 * @returns {SeverityCounts}
 */
export function calculateSeverityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
  }
  return counts;
}
