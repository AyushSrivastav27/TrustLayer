#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { scan } from './engine/scanner.js';

const program = new Command();

const ANSI_SHADOW_BANNER = `
████████╗██████╗ ██╗   ██╗███████╗████████╗██╗      █████╗ ██╗   ██╗███████╗██████╗ 
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
   ██║   ██████╔╝██║   ██║███████╗   ██║   ██║     ███████║ ╚████╔╝ █████╗  ██████╔╝
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗
   ██║   ██║  ██║╚██████╔╝███████║   ██║   ███████╗██║  ██║   ██║   ███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
`;

const SEVERITY_ICONS = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵'
};

const SUPPORTED_FORMATS = ['markdown', 'md', 'json'];

function printBanner() {
  console.log(chalk.cyan.bold(ANSI_SHADOW_BANNER));
  console.log(chalk.bold.white(' 🔍 TrustLayer Static Security Scanner v1.0.0'));
  console.log(chalk.gray('    Deterministic AST & Data-Flow Analysis for Node.js/Express'));
  console.log(chalk.gray(' ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
}

/**
 * Resolves destination report path and format automatically.
 *
 * @param {string|null} outputOption
 * @param {string} formatOption
 * @returns {{ filePath: string, format: string }}
 */
export function resolveReportTarget(outputOption, formatOption) {
  let format = (formatOption || 'markdown').toLowerCase();
  if (format === 'md') format = 'markdown';

  const defaultFileName = format === 'json' ? 'security-report.json' : 'SECURITY-REPORT.md';

  if (!outputOption || typeof outputOption !== 'string') {
    return {
      filePath: path.resolve(process.cwd(), defaultFileName),
      format
    };
  }

  let rawPath = outputOption.trim();
  const lower = rawPath.toLowerCase();

  if (lower.endsWith('.json')) {
    format = 'json';
  } else if (lower.endsWith('.md') || lower.endsWith('.markdown')) {
    format = 'markdown';
  } else {
    rawPath = format === 'json' ? `${rawPath}.json` : `${rawPath}.md`;
  }

  return {
    filePath: path.resolve(process.cwd(), rawPath),
    format
  };
}

/**
 * Generates a Markdown report from scan findings.
 *
 * @param {import('./types/report.js').ScanReport} report
 * @returns {string}
 */
export function generateMarkdownReport(report) {
  const { summary, findings, targetDirectory, scanDate } = report;
  const sev = summary.severities;

  let md = `# 🔒 TrustLayer Security Report\n\n`;
  md += `**Target**: \`${targetDirectory}\`  \n`;
  md += `**Scan Date**: ${scanDate}  \n`;
  md += `**Total Scanned Files**: ${summary.totalFiles}  \n`;
  md += `**Total Findings**: ${summary.totalFindings}  \n`;
  md += `**Summary**: 🔴 Critical: ${sev.critical} | 🟠 High: ${sev.high} | 🟡 Medium: ${sev.medium} | 🔵 Low: ${sev.low}\n\n`;
  md += `---\n\n`;

  if (findings.length === 0) {
    md += `## ✅ Clean Scan\n\nNo security issues were identified in this scan.\n`;
    return md;
  }

  for (const finding of findings) {
    const icon = SEVERITY_ICONS[finding.severity] || '⚪';
    const relFile = path.relative(process.cwd(), finding.file) || finding.file;
    md += `### ${icon} ${finding.severity.toUpperCase()}: ${finding.message}\n\n`;
    md += `- **File**: \`${relFile}:${finding.line}\`\n`;
    md += `- **Rule ID**: \`${finding.ruleId}\`\n`;
    md += `- **Confidence**: ${finding.confidence || 'high'}\n\n`;

    if (finding.codeSnippet) {
      md += `#### Vulnerable Code\n\`\`\`javascript\n${finding.codeSnippet}\n\`\`\`\n\n`;
    }

    if (finding.explanation) {
      md += `#### Why This Is Dangerous\n${finding.explanation}\n\n`;
    }

    if (finding.remediation) {
      md += `#### Recommended Remediation\n\`\`\`javascript\n${finding.remediation}\n\`\`\`\n\n`;
    }

    md += `---\n\n`;
  }

  return md;
}

const EXAMPLES_HELP = `
Examples:
  $ trustlayer                               Scan current directory (saves SECURITY-REPORT.md)
  $ trustlayer scan ./demo                   Scan a specific project directory
  $ trustlayer scan ./routes/checkout.js     Scan a single target file
  $ trustlayer scan ./demo -o audit -f json  Export audit results to JSON (audit.json)
  $ trustlayer scan ./demo -o report         Save report as report.md
  $ trustlayer scan --no-report              Print terminal results without saving a file
  $ trustlayer scan --ignore "**/dist/**"    Scan with custom glob ignore patterns
`;

program
  .name('trustlayer')
  .description('Deterministic static security scanner for Node.js/Express APIs')
  .version('1.0.0')
  .addHelpText('after', EXAMPLES_HELP);

program
  .command('scan', { isDefault: true })
  .description('Scan target directory or file for security vulnerabilities (default: current directory)')
  .argument('[target]', 'Target directory or file path to scan', '.')
  .option('-o, --output [file]', 'Output report path (auto-appends .md or .json, defaults to SECURITY-REPORT.md)')
  .option('-f, --format <format>', 'Report format: markdown or json', 'markdown')
  .option('-r, --rules-dir <path>', 'Custom directory to load security rules from')
  .option('--ignore <patterns...>', 'Additional glob patterns to ignore')
  .option('--no-report', 'Do not write any report file to disk (console output only)')
  .option('--no-banner', 'Suppress header banner')
  .addHelpText('after', EXAMPLES_HELP)
  .action(async (target, options) => {
    if (options.banner !== false) {
      printBanner();
    }

    const rawTarget = typeof target === 'string' ? target.trim() : '.';
    const resolvedTarget = path.resolve(process.cwd(), rawTarget);

    if (!fsSync.existsSync(resolvedTarget)) {
      console.error(chalk.red(`\n ❌ Error: Target path "${rawTarget}" does not exist.\n`));
      process.exit(2);
    }

    if (options.rulesDir) {
      const resolvedRulesDir = path.resolve(process.cwd(), options.rulesDir.trim());
      if (!fsSync.existsSync(resolvedRulesDir)) {
        console.error(chalk.red(`\n ❌ Error: Custom rules directory "${options.rulesDir}" does not exist.\n`));
        process.exit(2);
      }
    }

    const normalizedFormat = (options.format || 'markdown').trim().toLowerCase();
    if (!SUPPORTED_FORMATS.includes(normalizedFormat)) {
      console.error(chalk.red(`\n ❌ Error: Unsupported format "${options.format}". Allowed values: markdown, json.\n`));
      process.exit(2);
    }

    const sanitizedIgnore = Array.isArray(options.ignore)
      ? options.ignore.map(p => (typeof p === 'string' ? p.trim() : '')).filter(Boolean)
      : undefined;

    const spinner = ora({
      text: `Scanning files in ${chalk.cyan(path.relative(process.cwd(), resolvedTarget) || '.') }...`,
      color: 'cyan'
    }).start();

    try {
      const report = await scan(resolvedTarget, {
        rulesDir: options.rulesDir ? path.resolve(process.cwd(), options.rulesDir.trim()) : undefined,
        ignore: sanitizedIgnore,
        onProgress: ({ current, total, file }) => {
          spinner.text = `Scanning [${current}/${total}] ${chalk.gray(path.basename(file))}...`;
        }
      });

      spinner.stop();

      const { summary, findings } = report;
      const scanTime = `${summary.scanDurationMs}ms`;

      console.log(chalk.bold(` Scanned ${chalk.cyan(summary.totalFiles)} files in ${chalk.yellow(scanTime)}\n`));

      if (findings.length === 0) {
        console.log(chalk.green.bold(' ✅ No security issues found.\n'));
      } else {
        for (const finding of findings) {
          const icon = SEVERITY_ICONS[finding.severity] || '⚪';
          const sevLabel = (finding.severity || 'low').toUpperCase().padEnd(9);
          const colorFn = finding.severity === 'critical' ? chalk.red.bold
            : finding.severity === 'high' ? chalk.hex('#FFA500').bold
            : finding.severity === 'medium' ? chalk.yellow
            : chalk.blue;

          const relPath = path.relative(process.cwd(), finding.file) || finding.file;
          const loc = `${relPath}:${finding.line}`;
          const title = (finding.message || finding.ruleId).padEnd(32);

          console.log(` ${icon} ${colorFn(sevLabel)} ${chalk.white.bold(title)} ${chalk.gray(loc)}`);
        }

        console.log(chalk.gray('\n ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
        const counts = summary.severities;
        console.log(
          chalk.bold(
            ` Found ${findings.length} security issues (` +
            chalk.red(`${counts.critical} critical`) + ', ' +
            chalk.hex('#FFA500')(`${counts.high} high`) + ', ' +
            chalk.yellow(`${counts.medium} medium`) + ', ' +
            chalk.blue(`${counts.low} low`) + ')\n'
          )
        );
      }

      if (options.report !== false) {
        const { filePath, format } = resolveReportTarget(
          typeof options.output === 'string' ? options.output : null,
          normalizedFormat
        );

        let reportContent = '';
        if (format === 'json') {
          reportContent = JSON.stringify(report, null, 2);
        } else {
          try {
            const reporterModule = await import('./reporters/markdown-reporter.js');
            if (typeof reporterModule.generateMarkdownReport === 'function') {
              reportContent = reporterModule.generateMarkdownReport(report);
            } else if (typeof reporterModule.default === 'function') {
              reportContent = reporterModule.default(report);
            } else {
              reportContent = generateMarkdownReport(report);
            }
          } catch {
            reportContent = generateMarkdownReport(report);
          }
        }

        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, reportContent, 'utf-8');

        const displayPath = path.relative(process.cwd(), filePath) || filePath;
        console.log(chalk.cyan(` 📄 Full report saved: ${chalk.bold.underline(displayPath)}\n`));
      }

      const hasBlockers = (summary.severities.critical > 0 || summary.severities.high > 0);
      process.exit(hasBlockers ? 1 : 0);

    } catch (err) {
      spinner.fail(chalk.red(`Scan failed: ${err.message}`));
      process.exit(2);
    }
  });

let isDirectRun = false;
if (process.argv[1]) {
  try {
    const realArgv1 = fsSync.realpathSync(path.resolve(process.argv[1]));
    const thisFile = fileURLToPath(import.meta.url);
    isDirectRun = realArgv1 === thisFile;
  } catch {
    isDirectRun = false;
  }
}

if (isDirectRun) {
  program.parse(process.argv);
}

export { program };
