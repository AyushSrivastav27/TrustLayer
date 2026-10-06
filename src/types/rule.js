/**
 * @typedef {Object} AnalysisContext
 * @property {string} filePath - Absolute or relative path to the scanned file
 * @property {string} fileContent - Raw content of the file
 * @property {object|null} ast - Pre-parsed Babel AST (null if non-JS file)
 * @property {string[]} lines - File content split into line strings
 */

/**
 * @typedef {Object} Finding
 * @property {string} ruleId - Unique rule identifier (e.g. 'payment/client-controlled-amount')
 * @property {'critical'|'high'|'medium'|'low'} severity - Severity rating
 * @property {string} file - Path of the file where finding was detected
 * @property {number} line - Line number of the vulnerability (1-indexed)
 * @property {number} [endLine] - Optional end line number
 * @property {number} [column] - Optional column number
 * @property {string} codeSnippet - Excerpt of offending code
 * @property {string} message - High-level issue description
 * @property {string} [explanation] - Detailed explanation or attack scenario
 * @property {string} [remediation] - Code remediation advice
 * @property {'high'|'medium'|'low'} confidence - Confidence score of the finding
 */

/**
 * @typedef {Object} Rule
 * @property {string} id - Identifier in kebab-case (e.g. 'category/rule-name')
 * @property {string} name - Human-readable title
 * @property {'critical'|'high'|'medium'|'low'} severity - Severity classification
 * @property {'secrets'|'injection'|'payment'|'auth'} category - Security domain
 * @property {string} description - Summary of vulnerability
 * @property {string} defaultExplanation - Fallback explanation when AI is offline
 * @property {string} defaultRemediation - Secure code replacement snippet
 * @property {(context: AnalysisContext) => Finding[]} analyze - Execution function
 */

export {};
