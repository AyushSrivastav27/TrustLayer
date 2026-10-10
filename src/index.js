/**
 * TrustLayer — Programmatic Library API Entrypoint
 *
 * Exposes core static analysis engine functions, rule registry,
 * reporting generators, and AI enhancement primitives for ESM consumers.
 *
 * @module trustlayer
 */

import { scan, scanFile, SCANNER_VERSION } from './engine/scanner.js';
import { discoverFiles } from './engine/file-discovery.js';
import { parseSource } from './engine/ast-parser.js';
import { loadRules, VALID_SEVERITIES, VALID_CATEGORIES } from './engine/rule-registry.js';
import { enhanceReport } from './ai/enhancer.js';
import { generateMarkdownReport } from './reporters/markdown-reporter.js';
import { generateJsonReport, toSarif } from './reporters/json-reporter.js';
import { generateHtmlReport } from './reporters/html-reporter.js';

// Pre-load default rules for instant programmatic inspection
const defaultRules = await loadRules();

export {
  // Core Scanner Engine
  scan,
  scanFile,
  SCANNER_VERSION,

  // File Discovery & AST Parsing
  discoverFiles,
  parseSource,

  // Rule Registry & Rules
  loadRules,
  defaultRules as rules,
  VALID_SEVERITIES,
  VALID_CATEGORIES,

  // AI & Correlation Layer
  enhanceReport,

  // Report & SARIF Exporters
  generateMarkdownReport,
  generateHtmlReport,
  generateJsonReport,
  toSarif
};

export default {
  scan,
  scanFile,
  SCANNER_VERSION,
  discoverFiles,
  parseSource,
  loadRules,
  rules: defaultRules,
  VALID_SEVERITIES,
  VALID_CATEGORIES,
  enhanceReport,
  generateMarkdownReport,
  generateHtmlReport,
  generateJsonReport,
  toSarif
};
