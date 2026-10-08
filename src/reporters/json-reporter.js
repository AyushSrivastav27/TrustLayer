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

  const indent = options.pretty !== false ? 2 : 0;
  return JSON.stringify(report, null, indent);
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

  const sarifResults = findings.map(f => {
    const levelMap = {
      critical: 'error',
      high: 'error',
      medium: 'warning',
      low: 'note'
    };

    const normalizedSeverity = (f.severity || 'medium').toLowerCase();
    const filePath = (f.file || '').replace(/\\/g, '/');

    return {
      ruleId: f.ruleId,
      level: levelMap[normalizedSeverity] || 'warning',
      message: {
        text: f.message || f.ruleId || 'Security vulnerability detected'
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: filePath
            },
            region: {
              startLine: f.line || 1,
              startColumn: f.column || 1,
              endLine: f.endLine || f.line || 1
            }
          }
        }
      ]
    };
  });

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
            rules: Array.from(new Set(findings.map(f => f.ruleId))).map(id => {
              const matching = findings.find(f => f.ruleId === id);
              return {
                id,
                name: id.split('/').pop() || id,
                shortDescription: {
                  text: matching?.message || id
                },
                help: {
                  text: matching?.remediation || matching?.explanation || `Security rule: ${id}`
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
