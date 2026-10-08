import path from 'node:path';
import { getDeterministicScenario } from '../ai/enhancer.js';

const SEVERITY_BADGES = {
  critical: '🔴 **CRITICAL**',
  high: '🟠 **HIGH**',
  medium: '🟡 **MEDIUM**',
  low: '🔵 **LOW**'
};

const SEVERITY_ICONS = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵'
};

/**
 * Formats a ScanReport object into a comprehensive GitHub Flavored Markdown report.
 * Pure presentation layer: renders pre-enhanced findings and attack chains passed in the report.
 *
 * @param {import('../types/report.js').ScanReport} report - The security scan report object
 * @returns {string} Formatted Markdown content
 */
export function generateMarkdownReport(report) {
  if (!report) {
    return '# 🔒 TrustLayer Security Report\n\n*No scan report data available.*';
  }

  const {
    scannerVersion = '1.0.0',
    scanDate = new Date().toISOString(),
    targetDirectory = process.cwd(),
    summary = {
      totalFiles: 0,
      totalFindings: 0,
      severities: { critical: 0, high: 0, medium: 0, low: 0 },
      scanDurationMs: 0
    },
    findings = [],
    attackChains = [],
    aiMode,
    aiEngine
  } = report;

  const sev = summary.severities || { critical: 0, high: 0, medium: 0, low: 0 };
  const duration = summary.scanDurationMs ? `${summary.scanDurationMs}ms` : 'N/A';

  let md = `# 🛡️ TrustLayer Security Audit Report\n\n`;
  md += `> **Deterministic Static Security Scanner for Node.js & Express APIs**  \n`;
  md += `> *Scanner Version: v${scannerVersion}* | *Scan Date: ${scanDate}*\n\n`;
  md += `---\n\n`;

  // Executive Summary Card
  md += `## 📊 Executive Summary\n\n`;
  md += `| Metric | Value |\n`;
  md += `|:---|:---|\n`;
  md += `| **Target Scanned** | \`${targetDirectory}\` |\n`;
  md += `| **Files Analyzed** | **${summary.totalFiles}** files |\n`;
  md += `| **Scan Duration** | **${duration}** |\n`;
  md += `| **Total Issues Found** | **${summary.totalFindings}** |\n`;
  md += `| **Risk Profile** | 🔴 Critical: **${sev.critical}** \| 🟠 High: **${sev.high}** \| 🟡 Medium: **${sev.medium}** \| 🔵 Low: **${sev.low}** |\n`;

  if (aiMode || aiEngine) {
    const isOnline = aiMode === 'online';
    const engineLabel = isOnline
      ? `🌐 Online (${aiEngine || 'Google Gemini 3.8 Flash'} — Dynamic Exploit & Remediation Diffs)`
      : `🔌 Offline (${aiEngine || 'TrustLayer Deterministic Knowledge Graph'} — Air-Gapped Zero-Network)`;
    md += `| **AI Analysis Engine** | ${engineLabel} |\n`;
  }
  md += `\n`;

  // Clean Scan Section
  if (findings.length === 0) {
    md += `## ✅ Clean Scan — No Vulnerabilities Detected\n\n`;
    md += `All automated static analysis checks passed with zero security findings.  \n`;
    md += `No hardcoded secrets, SQL injection flaws, unverified webhooks, or payment tampering patterns were found in the scanned codebase.\n\n`;
    md += `---\n`;
    return md;
  }

  // Correlated Attack Chains (rendered purely from report presentation data)
  const activeChains = Array.isArray(attackChains) ? attackChains : [];

  if (activeChains.length > 0) {
    const chainHeader = aiMode === 'online'
      ? `## ⚡ Correlated Attack Chains (AI Online Correlated)\n\n`
      : `## ⚡ Correlated Attack Chains (AI Correlated)\n\n`;
    md += chainHeader;
    md += `The AI reasoning layer correlated multiple independent findings into the following composite exploit chains:\n\n`;

    for (const [index, chain] of activeChains.entries()) {
      const chainSev = (chain.severity || 'high').toUpperCase();
      const chainIcon = SEVERITY_ICONS[chain.severity] || '⚠️';

      md += `### ${chainIcon} Chain #${index + 1}: ${chain.title}\n\n`;
      md += `**Severity**: \`${chainSev}\`  \n`;
      if (chain.findingIds && chain.findingIds.length > 0) {
        md += `**Participating Rules**: ${chain.findingIds.map(id => `\`${id}\``).join(', ')}  \n`;
      }
      md += `\n${chain.description}\n\n`;
      md += `---\n\n`;
    }
  }

  // Findings Overview Table
  md += `## 📋 Findings Overview\n\n`;
  md += `| # | Severity | Rule ID | Location | Message |\n`;
  md += `|---|---|---|---|---|\n`;

  findings.forEach((f, idx) => {
    const relFile = f.file ? (path.relative(process.cwd(), f.file) || f.file) : 'unknown';
    const normalizedSev = (f.severity || 'unknown').toLowerCase();
    const badge = SEVERITY_BADGES[normalizedSev] || (f.severity || 'UNKNOWN').toUpperCase();
    const lineStr = f.line ? `:${f.line}` : '';
    const loc = `\`${relFile}${lineStr}\``;
    const safeMsg = String(f.message || f.ruleId || '').replace(/\|/g, '\\|');
    md += `| ${idx + 1} | ${badge} | \`${f.ruleId}\` | ${loc} | ${safeMsg} |\n`;
  });

  md += `\n---\n\n`;

  // Detailed Finding Cards
  md += `## 🔍 Detailed Vulnerability Breakdown\n\n`;

  findings.forEach((f, idx) => {
    const relFile = f.file ? (path.relative(process.cwd(), f.file) || f.file) : 'unknown';
    const normalizedSev = (f.severity || 'unknown').toLowerCase();
    const icon = SEVERITY_ICONS[normalizedSev] || '⚠️';
    const title = f.message || f.ruleId || 'Vulnerability Finding';

    md += `### ${icon} #${idx + 1} [${(f.severity || 'UNKNOWN').toUpperCase()}] ${title}\n\n`;
    md += `- **Rule**: \`${f.ruleId}\`\n`;
    const lineCol = f.line ? `:${f.line}${f.column ? `:${f.column}` : ''}` : '';
    md += `- **Location**: \`${relFile}${lineCol}\`\n`;
    md += `- **Confidence**: \`${(f.confidence || 'high').toUpperCase()}\`\n`;
    if (f.aiMode) {
      const provenanceLabel = f.aiMode === 'online'
        ? `\`🌐 Online — ${f.aiEngine || 'Gemini 3.8'}\``
        : `\`🔌 Offline — Local Heuristic\``;
      md += `- **AI Provenance**: ${provenanceLabel}\n`;
    }
    md += `\n`;

    if (f.codeSnippet) {
      md += `#### 🚨 Vulnerable Code\n`;
      const fence = f.codeSnippet.includes('```') ? '````' : '```';
      md += `${fence}javascript\n${f.codeSnippet}\n${fence}\n\n`;
    }

    if (f.explanation) {
      md += `#### 💥 Threat Assessment & Impact\n`;
      md += `${f.explanation}\n\n`;
    }

    const scenario = f.aiExploitScenario || (typeof getDeterministicScenario === 'function' ? getDeterministicScenario(f.ruleId) : null);
    if (scenario) {
      md += `#### 🎯 Step-by-Step Exploitation Scenario\n`;
      md += `${scenario}\n\n`;
    }

    if (f.remediation) {
      md += `#### 🛠️ Recommended Remediation\n`;
      if (typeof f.remediation === 'string' && f.remediation.trim().startsWith('```')) {
        md += `${f.remediation}\n\n`;
      } else {
        const fence = typeof f.remediation === 'string' && f.remediation.includes('```') ? '````' : '```';
        md += `${fence}javascript\n${f.remediation}\n${fence}\n\n`;
      }
    }

    md += `---\n\n`;
  });

  // Footer
  md += `*Generated automatically by [TrustLayer](https://github.com/vikalp1817243/TrustLayer) Static Security Scanner.*  \n`;
  md += `*Theme: "Shipped Fast, Left Open" — Cybersecurity Hackathon 2026*\n`;

  return md;
}

export default generateMarkdownReport;
