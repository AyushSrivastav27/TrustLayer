#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { execFileSync } from 'node:child_process';
import { scan, SCANNER_VERSION } from './engine/scanner.js';
import { generateMarkdownReport } from './reporters/markdown-reporter.js';

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
  console.log(chalk.bold.white(` 🔍 TrustLayer Static Security Scanner v${SCANNER_VERSION}`));
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

const EXAMPLES_HELP = `
Examples:
  $ trustlayer                               Scan current directory (saves SECURITY-REPORT.md)
  $ trustlayer scan ./demo                   Scan a specific project directory
  $ trustlayer scan ./routes/checkout.js     Scan a single target file
  $ trustlayer scan --staged                 Scan only files staged in git index (pre-commit mode)
  $ trustlayer scan -s critical,high         Filter findings to critical and high only
  $ trustlayer scan -c payment,auth          Filter findings to payment and auth categories
  $ trustlayer scan --fail-on critical       Exit code 1 triggered only on critical issues
  $ trustlayer scan ./demo -o audit -f json  Export audit results to JSON (audit.json)
  $ trustlayer scan ./demo -o report         Save report as report.md
  $ trustlayer scan --no-report              Print terminal results without saving a file
  $ trustlayer scan --ignore "**/dist/**"    Scan with custom glob ignore patterns
`;

program
  .name('trustlayer')
  .description('Deterministic static security scanner for Node.js/Express APIs')
  .version(SCANNER_VERSION)
  .addHelpText('after', EXAMPLES_HELP);

program
  .command('scan', { isDefault: true })
  .description('Scan target directory or file for security vulnerabilities (default: current directory)')
  .argument('[target]', 'Target directory or file path to scan', '.')
  .option('-o, --output [file]', 'Output report path (auto-appends .md or .json, defaults to SECURITY-REPORT.md)')
  .option('-f, --format <format>', 'Report format: markdown or json', 'markdown')
  .option('-r, --rules-dir <path>', 'Custom directory to load security rules from')
  .option('-s, --severity <levels>', 'Filter findings by severity (comma-separated: critical, high, medium, low)')
  .option('-c, --category <categories>', 'Filter findings by category (comma-separated: secrets, injection, payment, auth)')
  .option('--fail-on <level>', 'Minimum severity level to trigger exit code 1 (critical, high, medium, low, none)', 'high')
  .option('--staged', 'Scan only files staged in git index (pre-commit mode)')
  .option('--ignore <patterns...>', 'Additional glob patterns to ignore')
  .option('--no-report', 'Do not write any report file to disk (console output only)')
  .option('--no-banner', 'Suppress header banner')
  .addHelpText('after', EXAMPLES_HELP)
  .action(async (target, options) => {
    if (options.banner !== false) {
      printBanner();
    }

    const validFailOn = ['critical', 'high', 'medium', 'low', 'none'];
    const failOnLevel = (options.failOn || 'high').trim().toLowerCase();
    if (!validFailOn.includes(failOnLevel)) {
      console.error(chalk.red(`\n ❌ Error: Invalid --fail-on level "${options.failOn}". Allowed values: ${validFailOn.join(', ')}.\n`));
      process.exit(2);
    }

    let stagedFiles = null;
    if (options.staged) {
      try {
        const gitOutput = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], {
          encoding: 'utf-8',
          cwd: process.cwd()
        });
        const allStaged = gitOutput.split(/\r?\n/).map(f => f.trim()).filter(Boolean);
        const scannableRegex = /\.(?:[mc]?[jt]sx?)$/i;
        stagedFiles = allStaged
          .filter(f => scannableRegex.test(f) && !f.endsWith('.d.ts'))
          .map(f => path.resolve(process.cwd(), f))
          .filter(f => fsSync.existsSync(f));

        if (stagedFiles.length === 0) {
          console.log(chalk.green.bold(' ✅ No staged scannable files found. Pre-commit check passed.\n'));
          process.exit(0);
        }
      } catch (err) {
        console.error(chalk.red(`\n ❌ Error inspecting staged git files: ${err.message}\n`));
        process.exit(2);
      }
    }

    const rawTarget = typeof target === 'string' ? target.trim() : '.';
    const resolvedTarget = path.resolve(process.cwd(), rawTarget);

    if (!options.staged && !fsSync.existsSync(resolvedTarget)) {
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

    const selectedSeverities = typeof options.severity === 'string'
      ? options.severity.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
      : undefined;

    const selectedCategories = typeof options.category === 'string'
      ? options.category.split(',').map(c => c.trim().toLowerCase()).filter(Boolean)
      : undefined;

    const targetDesc = stagedFiles
      ? `${stagedFiles.length} staged file(s)`
      : (path.relative(process.cwd(), resolvedTarget) || '.');

    const spinner = ora({
      text: `Scanning files in ${chalk.cyan(targetDesc)}...`,
      color: 'cyan'
    }).start();

    try {
      const report = await scan(resolvedTarget, {
        rulesDir: options.rulesDir ? path.resolve(process.cwd(), options.rulesDir.trim()) : undefined,
        files: stagedFiles || undefined,
        severity: selectedSeverities,
        category: selectedCategories,
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
          reportContent = generateMarkdownReport(report);
        }

        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, reportContent, 'utf-8');

        const displayPath = path.relative(process.cwd(), filePath) || filePath;
        console.log(chalk.cyan(` 📄 Full report saved: ${chalk.bold.underline(displayPath)}\n`));
      }

      let hasBlockers = false;
      if (failOnLevel === 'critical') {
        hasBlockers = summary.severities.critical > 0;
      } else if (failOnLevel === 'high') {
        hasBlockers = summary.severities.critical > 0 || summary.severities.high > 0;
      } else if (failOnLevel === 'medium') {
        hasBlockers = summary.severities.critical > 0 || summary.severities.high > 0 || summary.severities.medium > 0;
      } else if (failOnLevel === 'low') {
        hasBlockers = summary.totalFindings > 0;
      } else if (failOnLevel === 'none') {
        hasBlockers = false;
      }

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

export { program, generateMarkdownReport };
