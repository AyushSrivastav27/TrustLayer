import path from 'node:path';
import { getDeterministicScenario } from '../ai/enhancer.js';

/**
 * Escapes characters for safe inclusion inside HTML text and attributes.
 *
 * @param {string|null|undefined} str
 * @returns {string}
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const SEVERITY_COLORS = {
  critical: { bg: 'rgba(239, 68, 68, 0.15)', border: '#EF4444', text: '#FCA5A5', badge: '#EF4444' },
  high:     { bg: 'rgba(249, 115, 22, 0.15)', border: '#F97316', text: '#FDBA74', badge: '#F97316' },
  medium:   { bg: 'rgba(245, 158, 11, 0.15)', border: '#F59E0B', text: '#FDE68A', badge: '#F59E0B' },
  low:      { bg: 'rgba(59, 130, 246, 0.15)', border: '#3B82F6', text: '#93C5FD', badge: '#3B82F6' }
};

/**
 * Generates an executive, interactive standalone HTML security report.
 * Air-gapped compatible: zero external network dependencies, fully self-contained CSS & JS.
 *
 * @param {import('../types/report.js').ScanReport} report
 * @returns {string} Formatted HTML document
 */
export function generateHtmlReport(report) {
  if (!report) {
    return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>TrustLayer Security Report</title></head>
<body style="font-family:sans-serif;padding:2rem;background:#0b0f19;color:#fff;">
  <h1>🛡️ TrustLayer Security Report</h1>
  <p>No scan report data available.</p>
</body>
</html>`;
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
  const hasFindings = findings.length > 0;
  const activeChains = Array.isArray(attackChains) ? attackChains : [];

  const aiEngineLabel = aiMode === 'online'
    ? `Online (${escapeHtml(aiEngine || 'Google Gemini 3.8 Flash')} — Dynamic Diffs)`
    : aiMode === 'offline'
      ? `Offline (${escapeHtml(aiEngine || 'Deterministic Knowledge Graph')} — Air-Gapped)`
      : null;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TrustLayer Security Audit Report</title>
  <style>
    :root {
      --bg: #0B0F19;
      --card-bg: #111827;
      --card-border: #1F2937;
      --text-main: #F3F4F6;
      --text-muted: #9CA3AF;
      --code-bg: #030712;
      --crit: #EF4444;
      --high: #F97316;
      --med: #F59E0B;
      --low: #3B82F6;
      --ok: #10B981;
      --accent: #6366F1;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding: 2rem 1rem;
      min-height: 100vh;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    /* Header */
    .header {
      background: linear-gradient(135deg, rgba(31, 41, 55, 0.7), rgba(17, 24, 39, 0.9));
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.75rem 2rem;
      margin-bottom: 2rem;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1.25rem;
    }

    .header-brand {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .logo-icon {
      font-size: 2.5rem;
      line-height: 1;
    }

    .title-group h1 {
      font-size: 1.85rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(90deg, #F3F4F6, #9CA3AF);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .title-group p {
      color: var(--text-muted);
      font-size: 0.875rem;
      margin-top: 0.25rem;
    }

    .header-meta {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 0.35rem;
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    .badge-tag {
      display: inline-block;
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .badge-online { background: rgba(99, 102, 241, 0.2); border: 1px solid #6366F1; color: #A5B4FC; }
    .badge-offline { background: rgba(59, 130, 246, 0.2); border: 1px solid #3B82F6; color: #93C5FD; }

    /* Summary Metrics Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .metric-card:hover {
      transform: translateY(-2px);
      border-color: rgba(255, 255, 255, 0.15);
    }

    .metric-label {
      font-size: 0.8rem;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }

    .metric-val {
      font-size: 1.85rem;
      font-weight: 800;
    }

    .metric-sub {
      font-size: 0.775rem;
      color: var(--text-muted);
    }

    /* Severity Bar */
    .severity-overview {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
    }

    .sev-pill-group {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }

    .sev-pill {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 0.85rem;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 600;
    }
    .sev-pill.crit { background: rgba(239, 68, 68, 0.15); border: 1px solid #EF4444; color: #FCA5A5; }
    .sev-pill.high { background: rgba(249, 115, 22, 0.15); border: 1px solid #F97316; color: #FDBA74; }
    .sev-pill.med  { background: rgba(245, 158, 11, 0.15); border: 1px solid #F59E0B; color: #FDE68A; }
    .sev-pill.low  { background: rgba(59, 130, 246, 0.15); border: 1px solid #3B82F6; color: #93C5FD; }

    /* Clean Scan Banner */
    .clean-scan-banner {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.12), rgba(6, 78, 59, 0.3));
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 12px;
      padding: 3rem 2rem;
      text-align: center;
      margin-bottom: 2rem;
    }

    .clean-scan-banner h2 {
      font-size: 1.75rem;
      font-weight: 800;
      color: #34D399;
      margin-top: 0.75rem;
    }

    .clean-scan-banner p {
      color: var(--text-muted);
      max-width: 650px;
      margin: 0.75rem auto 0;
      font-size: 0.95rem;
    }

    /* Attack Chains Section */
    .section-title {
      font-size: 1.35rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }

    .chains-container {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      margin-bottom: 2.5rem;
    }

    .chain-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(17, 24, 39, 0.9));
      border: 1px solid rgba(99, 102, 241, 0.3);
      border-radius: 10px;
      padding: 1.25rem 1.5rem;
    }

    .chain-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 0.65rem;
    }

    .chain-title {
      font-weight: 700;
      font-size: 1.1rem;
      color: #E0E7FF;
    }

    .chain-desc {
      color: #D1D5DB;
      font-size: 0.9rem;
      line-height: 1.6;
    }

    .chain-rules {
      margin-top: 0.75rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }

    .rule-tag {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.75rem;
      padding: 0.2rem 0.5rem;
      color: #C7D2FE;
    }

    /* Filter Toolbar */
    .toolbar {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 0.85rem 1.25rem;
      margin-bottom: 1.5rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .filter-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }

    .filter-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.825rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .filter-btn:hover {
      background: rgba(255, 255, 255, 0.1);
      color: var(--text-main);
    }
    .filter-btn.active {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }

    .search-input {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      color: var(--text-main);
      padding: 0.45rem 0.85rem;
      font-size: 0.85rem;
      min-width: 240px;
      outline: none;
    }
    .search-input:focus {
      border-color: var(--accent);
    }

    /* Findings Cards */
    .findings-container {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      margin-bottom: 3rem;
    }

    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      overflow: hidden;
      transition: border-color 0.15s ease;
    }
    .finding-card:hover {
      border-color: rgba(255, 255, 255, 0.2);
    }

    .finding-header {
      padding: 1rem 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.75rem;
      cursor: pointer;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid transparent;
      user-select: none;
    }
    .finding-card.open .finding-header {
      border-bottom-color: var(--card-border);
    }

    .finding-header-left {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex: 1;
      min-width: 280px;
    }

    .sev-badge {
      padding: 0.25rem 0.55rem;
      border-radius: 5px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      flex-shrink: 0;
    }
    .sev-badge.critical { background: var(--crit); color: #fff; }
    .sev-badge.high     { background: var(--high); color: #fff; }
    .sev-badge.medium   { background: var(--med);  color: #111; }
    .sev-badge.low      { background: var(--low);  color: #fff; }

    .finding-title {
      font-weight: 700;
      font-size: 0.975rem;
    }

    .finding-header-right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      color: var(--text-muted);
      font-size: 0.825rem;
      font-family: monospace;
    }

    .toggle-icon {
      font-size: 0.85rem;
      transition: transform 0.2s ease;
    }
    .finding-card.open .toggle-icon {
      transform: rotate(180deg);
    }

    .finding-body {
      display: none;
      padding: 1.25rem;
      flex-direction: column;
      gap: 1.25rem;
      background: rgba(0, 0, 0, 0.15);
    }
    .finding-card.open .finding-body {
      display: flex;
    }

    .finding-meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 1.5rem;
      font-size: 0.825rem;
      color: var(--text-muted);
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      padding-bottom: 0.85rem;
    }
    .meta-item strong { color: var(--text-main); }

    .content-block h4 {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }

    .code-box {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 0.85rem 1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 0.85rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      color: #E2E8F0;
      position: relative;
    }

    .remediation-box {
      border-left: 3px solid var(--ok);
      background: rgba(16, 185, 129, 0.05);
    }

    .exploit-box {
      border-left: 3px solid var(--crit);
      background: rgba(239, 68, 68, 0.05);
      color: #FCA5A5;
      padding: 0.85rem 1rem;
      border-radius: 6px;
      font-size: 0.9rem;
      line-height: 1.6;
    }

    .copy-btn {
      position: absolute;
      top: 0.5rem;
      right: 0.5rem;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.15);
      color: var(--text-muted);
      border-radius: 4px;
      padding: 0.2rem 0.5rem;
      font-size: 0.725rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .copy-btn:hover {
      background: rgba(255, 255, 255, 0.2);
      color: #fff;
    }

    /* Footer */
    .footer {
      border-top: 1px solid var(--card-border);
      padding-top: 1.75rem;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.85rem;
      line-height: 1.6;
    }
    .footer a {
      color: #818CF8;
      text-decoration: none;
    }
    .footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="header-brand">
        <span class="logo-icon">🛡️</span>
        <div class="title-group">
          <h1>TrustLayer Security Audit Report</h1>
          <p>Deterministic Static Security Scanner for Node.js &amp; Express APIs</p>
        </div>
      </div>
      <div class="header-meta">
        <div>Scanner Version: <strong>v${escapeHtml(scannerVersion)}</strong></div>
        <div>Scan Date: <strong>${escapeHtml(scanDate)}</strong></div>
        ${aiEngineLabel ? `<div class="badge-tag ${aiMode === 'online' ? 'badge-online' : 'badge-offline'}">${aiEngineLabel}</div>` : ''}
      </div>
    </header>

    <!-- Metrics Grid -->
    <section class="metrics-grid">
      <div class="metric-card">
        <span class="metric-label">Target Scanned</span>
        <span class="metric-val" style="font-size: 1.15rem; word-break: break-all;">${escapeHtml(targetDirectory)}</span>
        <span class="metric-sub">Intra-handler AST analysis</span>
      </div>
      <div class="metric-card">
        <span class="metric-label">Files Analyzed</span>
        <span class="metric-val">${summary.totalFiles}</span>
        <span class="metric-sub">Scanned in ${escapeHtml(duration)}</span>
      </div>
      <div class="metric-card">
        <span class="metric-label">Total Findings</span>
        <span class="metric-val" style="color: ${hasFindings ? 'var(--crit)' : 'var(--ok)'};">${summary.totalFindings}</span>
        <span class="metric-sub">${hasFindings ? 'Action required before deploy' : 'Deployment gate passed'}</span>
      </div>
      <div class="metric-card">
        <span class="metric-label">Risk Rating</span>
        <span class="metric-val" style="font-size: 1.35rem; color: ${sev.critical > 0 ? 'var(--crit)' : sev.high > 0 ? 'var(--high)' : 'var(--ok)'};">
          ${sev.critical > 0 ? 'CRITICAL' : sev.high > 0 ? 'HIGH' : hasFindings ? 'MEDIUM/LOW' : 'CLEAN'}
        </span>
        <span class="metric-sub">${activeChains.length} Correlated Chain(s)</span>
      </div>
    </section>

    <!-- Severity Overview Bar -->
    <section class="severity-overview">
      <span class="metric-label" style="font-size: 0.9rem;">Severity Breakdown</span>
      <div class="sev-pill-group">
        <div class="sev-pill crit">🔴 Critical: <strong>${sev.critical}</strong></div>
        <div class="sev-pill high">🟠 High: <strong>${sev.high}</strong></div>
        <div class="sev-pill med">🟡 Medium: <strong>${sev.medium}</strong></div>
        <div class="sev-pill low">🔵 Low: <strong>${sev.low}</strong></div>
      </div>
    </section>

    ${!hasFindings ? `
    <!-- Clean Scan Banner -->
    <section class="clean-scan-banner">
      <div style="font-size: 3rem;">✅</div>
      <h2>100% Clean Scan — Zero Flaws Detected</h2>
      <p>All automated static security checks passed. No hardcoded secrets, SQL injection flaws, missing auth guards, or payment amount tampering patterns were discovered in the target application.</p>
    </section>
    ` : ''}

    ${activeChains.length > 0 ? `
    <!-- Correlated Attack Chains -->
    <h3 class="section-title">⚡ Correlated Attack Chains (${activeChains.length})</h3>
    <section class="chains-container">
      ${activeChains.map((chain, idx) => `
        <article class="chain-card">
          <div class="chain-header">
            <span class="chain-title">#${idx + 1} ${escapeHtml(chain.title)}</span>
            <span class="sev-badge ${escapeHtml((chain.severity || 'high').toLowerCase())}">${escapeHtml((chain.severity || 'high').toUpperCase())}</span>
          </div>
          <p class="chain-desc">${escapeHtml(chain.description)}</p>
          ${chain.findingIds && chain.findingIds.length > 0 ? `
            <div class="chain-rules">
              <span style="font-size: 0.75rem; color: var(--text-muted); align-self: center;">Participating Rules:</span>
              ${chain.findingIds.map(id => `<span class="rule-tag">${escapeHtml(id)}</span>`).join('')}
            </div>
          ` : ''}
        </article>
      `).join('')}
    </section>
    ` : ''}

    ${hasFindings ? `
    <!-- Filter Toolbar -->
    <section class="toolbar">
      <div class="filter-tabs">
        <button class="filter-btn active" data-filter="all">All (${findings.length})</button>
        <button class="filter-btn" data-filter="critical">Critical (${sev.critical})</button>
        <button class="filter-btn" data-filter="high">High (${sev.high})</button>
        <button class="filter-btn" data-filter="medium">Medium (${sev.medium})</button>
        <button class="filter-btn" data-filter="low">Low (${sev.low})</button>
      </div>
      <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search by rule, file, keyword...">
    </section>

    <!-- Findings Accordion -->
    <section class="findings-container" id="findingsContainer">
      ${findings.map((f, idx) => {
        const relFile = f.file ? (path.relative(process.cwd(), f.file) || f.file) : 'unknown';
        const normalizedSev = (f.severity || 'low').toLowerCase();
        const lineCol = f.line ? `:${f.line}${f.column ? `:${f.column}` : ''}` : '';
        const scenario = f.aiExploitScenario || (typeof getDeterministicScenario === 'function' ? getDeterministicScenario(f.ruleId) : null);

        return `
        <article class="finding-card open" data-severity="${escapeHtml(normalizedSev)}" data-search="${escapeHtml(`${f.ruleId} ${relFile} ${f.message || ''}`.toLowerCase())}">
          <header class="finding-header" onclick="toggleCard(this)">
            <div class="finding-header-left">
              <span class="sev-badge ${escapeHtml(normalizedSev)}">${escapeHtml(normalizedSev)}</span>
              <span class="finding-title">#${idx + 1} ${escapeHtml(f.message || f.ruleId)}</span>
            </div>
            <div class="finding-header-right">
              <span>${escapeHtml(relFile)}${escapeHtml(lineCol)}</span>
              <span class="toggle-icon">▼</span>
            </div>
          </header>
          <div class="finding-body">
            <div class="finding-meta-row">
              <div class="meta-item">Rule ID: <strong><code>${escapeHtml(f.ruleId)}</code></strong></div>
              <div class="meta-item">Confidence: <strong>${escapeHtml((f.confidence || 'high').toUpperCase())}</strong></div>
              <div class="meta-item">Location: <strong><code>${escapeHtml(relFile)}${escapeHtml(lineCol)}</code></strong></div>
              ${f.aiMode ? `<div class="meta-item">AI Provenance: <strong>${escapeHtml(f.aiMode)}</strong></div>` : ''}
            </div>

            ${f.codeSnippet ? `
            <div class="content-block">
              <h4>🚨 Vulnerable Code Snippet</h4>
              <div class="code-box">
                <button class="copy-btn" onclick="copyCode(this)">Copy</button>
                <code>${escapeHtml(f.codeSnippet.trim())}</code>
              </div>
            </div>
            ` : ''}

            ${f.explanation ? `
            <div class="content-block">
              <h4>💥 Threat Assessment &amp; Impact</h4>
              <p style="color: #D1D5DB; font-size: 0.925rem; line-height: 1.6;">${escapeHtml(f.explanation)}</p>
            </div>
            ` : ''}

            ${scenario ? `
            <div class="content-block">
              <h4>🎯 Step-by-Step Exploitation Scenario</h4>
              <div class="exploit-box">${escapeHtml(scenario)}</div>
            </div>
            ` : ''}

            ${f.remediation ? `
            <div class="content-block">
              <h4>🛠️ Recommended Secure Remediation</h4>
              <div class="code-box remediation-box">
                <button class="copy-btn" onclick="copyCode(this)">Copy</button>
                <code>${escapeHtml(f.remediation.trim())}</code>
              </div>
            </div>
            ` : ''}
          </div>
        </article>`;
      }).join('')}
    </section>
    ` : ''}

    <!-- Footer -->
    <footer class="footer">
      <p>Generated by <a href="https://github.com/vikalp1817243/TrustLayer" target="_blank" rel="noopener">TrustLayer</a> Static Security Scanner • Version ${escapeHtml(scannerVersion)}</p>
      <p>Cybersecurity Hackathon 2026 — Theme: <em>"Shipped Fast, Left Open"</em></p>
    </footer>
  </div>

  <script>
    function toggleCard(header) {
      const card = header.closest('.finding-card');
      card.classList.toggle('open');
    }

    function copyCode(btn) {
      const code = btn.nextElementSibling.innerText;
      navigator.clipboard.writeText(code).then(() => {
        const originalText = btn.innerText;
        btn.innerText = 'Copied!';
        btn.style.color = '#10B981';
        setTimeout(() => {
          btn.innerText = originalText;
          btn.style.color = '';
        }, 1500);
      });
    }

    // Filter by severity tabs
    const filterButtons = document.querySelectorAll('.filter-btn');
    const cards = document.querySelectorAll('.finding-card');
    const searchInput = document.getElementById('searchInput');

    let currentFilter = 'all';
    let searchQuery = '';

    function applyFilters() {
      cards.forEach(card => {
        const sev = card.getAttribute('data-severity');
        const searchContent = card.getAttribute('data-search') || '';
        const matchesFilter = (currentFilter === 'all' || sev === currentFilter);
        const matchesSearch = !searchQuery || searchContent.includes(searchQuery);

        if (matchesFilter && matchesSearch) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }

    filterButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        filterButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.getAttribute('data-filter');
        applyFilters();
      });
    });

    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.toLowerCase().trim();
        applyFilters();
      });
    }
  </script>
</body>
</html>`;
}
