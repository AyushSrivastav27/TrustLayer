/**
 * Severity level of a vulnerability finding.
 * @typedef {'critical' | 'high' | 'medium' | 'low'} Severity
 */

/**
 * Confidence score indicating likelihood of a true positive.
 * @typedef {'high' | 'medium' | 'low'} Confidence
 */

/**
 * Represents a single security vulnerability detected by a rule.
 * @typedef {Object} Finding
 * @property {string} ruleId - Unique rule identifier (e.g., 'payment/client-controlled-amount')
 * @property {Severity} severity - Severity classification ('critical' | 'high' | 'medium' | 'low')
 * @property {'secrets' | 'injection' | 'payment' | 'auth'} [category] - Security category classification
 * @property {string} file - Relative or absolute path to the vulnerable file
 * @property {number} line - Starting line number of the vulnerability (1-indexed)
 * @property {number} [endLine] - Optional ending line number (1-indexed)
 * @property {number} [column] - Optional starting column position
 * @property {string} codeSnippet - The exact code snippet exhibiting the vulnerability
 * @property {string} message - Clear, high-level summary of the issue detected
 * @property {string} [explanation] - Detailed explanation or attack scenario (AI-enhanced or default)
 * @property {string} [remediation] - Code remediation advice or recommended fix pattern
 * @property {Confidence} confidence - Confidence rating of the detection ('high' | 'medium' | 'low')
 */

/**
 * Optional helper factory to create and validate a Finding object.
 *
 * @param {Finding} finding
 * @returns {Finding}
 */
export function createFinding(finding) {
  const validSeverities = ['critical', 'high', 'medium', 'low'];
  const validConfidences = ['high', 'medium', 'low'];

  if (!finding.ruleId || !finding.file || typeof finding.line !== 'number') {
    throw new Error('Finding requires ruleId, file, and line properties.');
  }

  if (!validSeverities.includes(finding.severity)) {
    throw new Error(`Invalid severity "${finding.severity}". Must be one of: ${validSeverities.join(', ')}`);
  }

  if (finding.confidence && !validConfidences.includes(finding.confidence)) {
    throw new Error(`Invalid confidence "${finding.confidence}". Must be one of: ${validConfidences.join(', ')}`);
  }

  return {
    ...finding,
    confidence: finding.confidence || 'high'
  };
}
