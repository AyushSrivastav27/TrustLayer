import path from 'node:path';

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
 * Normalizes a file path for display.
 * If the path is absolute, converts it to relative against process.cwd().
 * If already relative, preserves it cleanly.
 *
 * @param {string} [filePath]
 * @returns {string}
 */
export function formatDisplayPath(filePath) {
  if (!filePath || typeof filePath !== 'string') return 'unknown';
  if (path.isAbsolute(filePath)) {
    return path.relative(process.cwd(), filePath) || filePath;
  }
  return filePath;
}

/**
 * Formats a ScanReport object into a comprehensive GitHub Flavored Markdown report.
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
    attackChains = []
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
  md += `| **Risk Profile** | 🔴 Critical: **${sev.critical}** \| 🟠 High: **${sev.high}** \| 🟡 Medium: **${sev.medium}** \| 🔵 Low: **${sev.low}** |\n\n`;

  const safeFindings = Array.isArray(findings) ? findings.filter(f => f && typeof f === 'object') : [];

  // Clean Scan Section
  if (safeFindings.length === 0) {
    md += `## ✅ Clean Scan — No Vulnerabilities Detected\n\n`;
    md += `All automated static analysis checks passed with zero security findings.  \n`;
    md += `No hardcoded secrets, SQL injection flaws, unverified webhooks, or payment tampering patterns were found in the scanned codebase.\n\n`;
    md += `---\n`;
    return md;
  }

  // Correlated Attack Chains (rendered from report if present)
  const activeChains = Array.isArray(attackChains) ? attackChains.filter(c => c && typeof c === 'object') : [];

  if (activeChains.length > 0) {
    md += `## ⚡ Correlated Attack Chains (AI Correlated)\n\n`;
    md += `The AI reasoning layer correlated multiple independent findings into the following composite exploit chains:\n\n`;

    for (const [index, chain] of activeChains.entries()) {
      const chainSev = String(chain.severity || 'high').toUpperCase();
      const chainIcon = SEVERITY_ICONS[String(chain.severity || '').toLowerCase()] || '⚠️';
      const chainTitle = chain.title || chain.name || `Chain #${index + 1}`;

      md += `### ${chainIcon} Chain #${index + 1}: ${chainTitle}\n\n`;
      md += `**Severity**: \`${chainSev}\`  \n`;
      const chainFindingIds = Array.isArray(chain.findingIds) ? chain.findingIds : (Array.isArray(chain.findings) ? chain.findings : []);
      if (chainFindingIds.length > 0) {
        md += `**Participating Rules**: ${chainFindingIds.map(id => `\`${id}\``).join(', ')}  \n`;
      }
      const narrative = chain.description || chain.narrative;
      if (narrative) {
        md += `\n${narrative}\n\n`;
      }
      md += `---\n\n`;
    }
  }

  // Findings Overview Table
  md += `## 📋 Findings Overview\n\n`;
  md += `| # | Severity | Rule ID | Location | Message |\n`;
  md += `|---|---|---|---|---|\n`;

  safeFindings.forEach((f, idx) => {
    const relFile = formatDisplayPath(f.file);
    const normalizedSev = String(f.severity || 'unknown').toLowerCase();
    const badge = SEVERITY_BADGES[normalizedSev] || String(f.severity || 'UNKNOWN').toUpperCase();
    const lineStr = f.line ? `:${f.line}` : '';
    const loc = `\`${relFile}${lineStr}\``;
    const safeMsg = String(f.message || f.ruleId || '').replace(/\|/g, '\\|');
    md += `| ${idx + 1} | ${badge} | \`${f.ruleId || 'unknown'}\` | ${loc} | ${safeMsg} |\n`;
  });

  md += `\n---\n\n`;

  // Detailed Finding Cards
  md += `## 🔍 Detailed Vulnerability Breakdown\n\n`;

  safeFindings.forEach((f, idx) => {
    const relFile = formatDisplayPath(f.file);
    const normalizedSev = String(f.severity || 'unknown').toLowerCase();
    const icon = SEVERITY_ICONS[normalizedSev] || '⚠️';
    const title = f.message || f.ruleId || 'Vulnerability Finding';

    md += `### ${icon} #${idx + 1} [${String(f.severity || 'UNKNOWN').toUpperCase()}] ${title}\n\n`;
    md += `- **Rule**: \`${f.ruleId || 'unknown'}\`\n`;
    const lineCol = f.line ? `:${f.line}${f.column ? `:${f.column}` : ''}` : '';
    md += `- **Location**: \`${relFile}${lineCol}\`\n`;
    md += `- **Confidence**: \`${String(f.confidence || 'high').toUpperCase()}\`\n\n`;

    if (f.codeSnippet) {
      md += `#### 🚨 Vulnerable Code\n`;
      const fence = String(f.codeSnippet).includes('```') ? '````' : '```';
      md += `${fence}javascript\n${f.codeSnippet}\n${fence}\n\n`;
    }

    if (f.explanation) {
      md += `#### 💥 Threat Assessment & Impact\n`;
      md += `${f.explanation}\n\n`;
    }

    const scenario = typeof f.aiExploitScenario === 'string' ? f.aiExploitScenario : null;
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
