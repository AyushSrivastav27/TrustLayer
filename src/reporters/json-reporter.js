import path from 'node:path';

/**
 * Generates a formatted JSON representation of a security scan report.
 *
 * @param {import('../types/report.js').ScanReport} report - Complete scan report
 * @param {Object} [options]
 * @param {boolean} [options.pretty=true] - Whether to pretty-print with indentation
 * @returns {string} Serialized JSON string
 */
export function generateJsonReport(report, options = { pretty: true }) {
  if (!report) {
    return JSON.stringify({ error: 'No scan report provided' }, null, 2);
  }

  const opts = options || {};
  const indent = opts.pretty !== false ? 2 : 0;
  try {
    return JSON.stringify(report, null, indent);
  } catch (err) {
    return JSON.stringify({ error: 'Serialization failed', message: err.message }, null, indent);
  }
}

/**
 * Converts a TrustLayer ScanReport into standard SARIF v2.1.0 format
 * for direct integration into GitHub Code Scanning and CI/CD pipelines.
 *
 * @param {import('../types/report.js').ScanReport} report
 * @returns {object} SARIF document object
 */
export function toSarif(report) {
  const { scannerVersion = '1.0.0', findings = [] } = report || {};
  const safeFindings = Array.isArray(findings)
    ? findings.filter(f => f && typeof f === 'object')
    : [];

  const levelMap = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note'
  };

  const sarifResults = safeFindings.map(f => {
    const normalizedSeverity = (f.severity || 'medium').toLowerCase();
    let filePath = (f.file || '').replace(/\\/g, '/');
    if (path.isAbsolute(f.file || '')) {
      const cwd = process.cwd().replace(/\\/g, '/');
      if (filePath.startsWith(cwd + '/')) {
        filePath = filePath.slice(cwd.length + 1);
      }
    }
    if (filePath.startsWith('./')) {
      filePath = filePath.slice(2);
    }

    const region = {
      startLine: typeof f.line === 'number' && f.line > 0 ? f.line : 1,
      startColumn: typeof f.column === 'number' && f.column > 0 ? f.column : 1,
      endLine: typeof f.endLine === 'number' && f.endLine > 0 ? f.endLine : (typeof f.line === 'number' && f.line > 0 ? f.line : 1)
    };

    if (typeof f.endColumn === 'number' && f.endColumn > 0) {
      region.endColumn = f.endColumn;
    }

    return {
      ruleId: f.ruleId || 'unknown-rule',
      level: levelMap[normalizedSeverity] || 'warning',
      message: {
        text: f.message || f.ruleId || 'Security vulnerability detected'
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: filePath,
              uriBaseId: '%SRCROOT%'
            },
            region
          }
        }
      ]
    };
  });

  const uniqueRuleIds = Array.from(new Set(safeFindings.map(f => f.ruleId).filter(Boolean)));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'TrustLayer',
            version: scannerVersion,
            informationUri: 'https://github.com/vikalp1817243/TrustLayer',
            rules: uniqueRuleIds.map(id => {
              const matching = safeFindings.find(f => f.ruleId === id);
              const category = matching?.category || id.split('/')[0] || 'security';
              const severity = (matching?.severity || 'medium').toLowerCase();
              return {
                id,
                name: id.split('/').pop() || id,
                shortDescription: {
                  text: matching?.message || id
                },
                fullDescription: {
                  text: matching?.explanation || matching?.message || id
                },
                helpUri: 'https://github.com/vikalp1817243/TrustLayer',
                help: {
                  text: matching?.remediation || matching?.explanation || `Security rule: ${id}`,
                  markdown: `### Vulnerability\n${matching?.explanation || matching?.message || id}\n\n### Remediation\n\`\`\`javascript\n${matching?.remediation || '// Remediate vulnerability'}\n\`\`\``
                },
                properties: {
                  category,
                  tags: [
                    'security',
                    category,
                    `severity/${severity}`
                  ]
                },
                defaultConfiguration: {
                  level: levelMap[severity] || 'warning'
                }
              };
            })
          }
        },
        results: sarifResults
      }
    ]
  };
}

export default generateJsonReport;
