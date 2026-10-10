#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { execFileSync } from 'node:child_process';
import dotenv from 'dotenv';
import { scan, SCANNER_VERSION } from './engine/scanner.js';
import { generateMarkdownReport } from './reporters/markdown-reporter.js';
import { generateJsonReport, toSarif } from './reporters/json-reporter.js';
import { generateHtmlReport } from './reporters/html-reporter.js';

// Auto-load .env from current directory at startup
dotenv.config();

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

const SUPPORTED_FORMATS = ['markdown', 'md', 'html', 'htm', 'json', 'sarif'];

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

  let defaultFileName = 'SECURITY-REPORT.md';
  if (format === 'json') defaultFileName = 'security-report.json';
  if (format === 'sarif') defaultFileName = 'security-report.sarif';
  if (format === 'html') defaultFileName = 'SECURITY-REPORT.html';

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
  } else if (lower.endsWith('.sarif')) {
    format = 'sarif';
  } else if (lower.endsWith('.html') || lower.endsWith('.htm')) {
    format = 'html';
  } else if (lower.endsWith('.md') || lower.endsWith('.markdown')) {
    format = 'markdown';
  } else {
    if (format === 'json') rawPath = `${rawPath}.json`;
    else if (format === 'sarif') rawPath = `${rawPath}.sarif`;
    else if (format === 'html') rawPath = `${rawPath}.html`;
    else rawPath = `${rawPath}.md`;
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
  $ trustlayer scan -a                       Enhance scan with AI attack chains & exploit scenarios
  $ trustlayer scan --ai --api-key <key>     Run online AI analysis with provided key (Gemini / Claude / OpenAI)
  $ trustlayer scan ./demo -v                Show verbose remediation code snippets in terminal
  $ trustlayer scan ./demo -av               Combined flags: AI attack chains + verbose terminal output
  $ trustlayer scan ./routes/checkout.js     Scan a single target file
  $ trustlayer scan --staged                 Scan only files staged in git index (pre-commit mode)
  $ trustlayer scan -s critical,high         Filter findings to critical and high only
  $ trustlayer scan -c payment,auth          Filter findings to payment and auth categories
  $ trustlayer scan --fail-on critical       Exit code 1 triggered only on critical issues
  $ trustlayer scan ./demo -o audit -f json  Export audit results to JSON (audit.json)
  $ trustlayer scan ./demo -o audit -f sarif Export audit results to SARIF for GitHub Code Scanning
  $ trustlayer scan ./demo -f html           Export audit results to standalone HTML (SECURITY-REPORT.html)
  $ trustlayer scan ./demo -o report         Save report as report.md
  $ trustlayer scan --no-report              Print terminal results without saving a file
  $ trustlayer scan --ignore "**/dist/**"    Scan with custom glob ignore patterns
`;

program
  .name('trustlayer')
  .description('Deterministic static security scanner for Node.js/Express APIs')
  .version(SCANNER_VERSION)
  .addHelpText('after', EXAMPLES_HELP)
  .exitOverride((err) => {
    if (err.code === 'commander.helpDisplayed' || err.code === 'commander.version') {
      process.exit(0);
    }
    process.exit(2);
  });

program
  .command('scan', { isDefault: true })
  .description('Scan target directory or file for security vulnerabilities (default: current directory)')
  .argument('[target]', 'Target directory or file path to scan', '.')
  .option('-o, --output [file]', 'Output report path (auto-appends .md, .html, .json, or .sarif, defaults to SECURITY-REPORT.md + SECURITY-REPORT.html)')
  .option('-f, --format <format>', 'Report format: markdown, html, json, or sarif', 'markdown')
  .option('-r, --rules-dir <path>', 'Custom directory to load security rules from')
  .option('-s, --severity <levels>', 'Filter findings by severity (comma-separated: critical, high, medium, low)')
  .option('-c, --category <categories>', 'Filter findings by category (comma-separated: secrets, injection, payment, auth)')
  .option('--fail-on <level>', 'Minimum severity level to trigger exit code 1 (critical, high, medium, low, none)', 'high')
  .option('-a, --ai', 'Enable AI-powered exploit scenario generation and attack chain correlation')
  .option('--api-key <key>', 'API key for online AI analysis (Google Gemini or OpenAI)')
  .option('-v, --verbose', 'Display exploit scenarios and remediation code snippets in terminal output')
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

    // Attempt to load .env from target directory if different from cwd
    const targetEnvPath = path.join(resolvedTarget, '.env');
    if (fsSync.existsSync(targetEnvPath)) {
      dotenv.config({ path: targetEnvPath });
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
      console.error(chalk.red(`\n ❌ Error: Unsupported format "${options.format}". Allowed values: markdown, html, json, sarif.\n`));
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

    // Multi-tier API key resolution for AI mode
    let apiKey = null;
    if (options.apiKey && typeof options.apiKey === 'string') {
      apiKey = options.apiKey.trim();
      console.warn(chalk.yellow(' ⚠️  Warning: Passing API keys via command-line arguments may expose them in shell history. Consider using the GEMINI_API_KEY environment variable or a local .env file instead.\n'));
    } else if (process.env.GEMINI_API_KEY) {
      apiKey = process.env.GEMINI_API_KEY.trim();
    } else if (process.env.GOOGLE_API_KEY) {
      apiKey = process.env.GOOGLE_API_KEY.trim();
    } else if (process.env.ANTHROPIC_API_KEY) {
      apiKey = process.env.ANTHROPIC_API_KEY.trim();
    } else if (process.env.CLAUDE_API_KEY) {
      apiKey = process.env.CLAUDE_API_KEY.trim();
    } else if (process.env.OPENAI_API_KEY) {
      apiKey = process.env.OPENAI_API_KEY.trim();
    }

    // Display AI mode banner if --ai requested
    if (options.ai) {
      if (apiKey) {
        const isClaude = apiKey.startsWith('sk-ant-') || Boolean(process.env.ANTHROPIC_API_KEY) || Boolean(process.env.CLAUDE_API_KEY);
        const isGemini = !isClaude && (apiKey.startsWith('AIza') || apiKey.startsWith('AQ.') || Boolean(process.env.GEMINI_API_KEY) || Boolean(process.env.GOOGLE_API_KEY));
        const providerName = isClaude
          ? 'Anthropic Claude (Auto-Fallback: 3.7 Sonnet / 3.5 Sonnet / 3.5 Haiku)'
          : isGemini
            ? 'Google Gemini (Auto-Fallback: 3.8 / 3.7 / 3.6 / 3.5 Flash)'
            : 'OpenAI gpt-4o-mini';
        console.log(chalk.cyan.bold(` ⚡ AI Mode: 🌐 ONLINE (${providerName}) — Generating contextual exploit diffs & attack chains\n`));
      } else {
        console.log(chalk.blue.bold(' 🛡️  AI Mode: 🔌 OFFLINE (Deterministic Heuristic Engine — Zero-Network Privacy)\n'));
      }
    }

    const isInteractive = Boolean(process.stdout.isTTY && !process.env.CI);

    const spinner = ora({
      text: `Scanning files in ${chalk.cyan(targetDesc)}...`,
      color: 'cyan',
      isSilent: !isInteractive
    }).start();

    try {
      let report = await scan(resolvedTarget, {
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

      // If AI mode enabled, enhance report with attack chains and exploit scenarios
      if (options.ai) {
        const aiSpinner = ora({
          text: 'Enhancing findings with AI exploit scenarios and correlating attack chains...',
          color: 'magenta',
          isSilent: !isInteractive
        }).start();

        try {
          const { enhanceReport } = await import('./ai/enhancer.js');
          report = await enhanceReport(report, { apiKey });
        } catch {
          // Gracefully continue with raw report if enhancer fails
        } finally {
          aiSpinner.stop();
        }

        // Notify if user requested online with key, but API fell back to offline
        if (apiKey && report.aiMode === 'offline') {
          console.log(chalk.yellow(' ℹ️  Cloud AI API was unreachable or unauthenticated. Fell back to Deterministic Offline Engine.\n'));
        }
      }

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

          let provenanceTag = '';
          if (options.ai) {
            provenanceTag = finding.aiMode === 'online'
              ? chalk.cyan('[AI: Online]') + ' '
              : chalk.gray('[AI: Offline]') + ' ';
          }

          console.log(` ${icon} ${colorFn(sevLabel)} ${chalk.white.bold(title)} ${provenanceTag}${chalk.gray(loc)}`);

          if (options.verbose) {
            if (finding.codeSnippet) {
              console.log(chalk.gray(`    Snippet: ${finding.codeSnippet.trim()}`));
            }
            if (finding.aiExploitScenario) {
              const firstLineScenario = finding.aiExploitScenario.split('\n')[0] || finding.aiExploitScenario;
              console.log(chalk.hex('#FFB86C')(`    🎯 Exploit: ${firstLineScenario}`));
            }
            if (finding.remediation) {
              const firstLineRemediation = finding.remediation.split('\n')[0] || finding.remediation;
              console.log(chalk.green(`    🛠️  Fix: ${firstLineRemediation}`));
            }
            console.log('');
          }
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

        // Display correlated attack chains if present
        if (report.attackChains && report.attackChains.length > 0) {
          console.log(chalk.bold.magenta(' ⚡ Correlated Attack Chains (Composite Vulnerabilities):'));
          for (const [idx, chain] of report.attackChains.entries()) {
            const chainIcon = SEVERITY_ICONS[chain.severity] || '⚠️';
            const chainSev = (chain.severity || 'high').toUpperCase();
            console.log(`\n  ${chainIcon} ${chalk.bold.white(`Chain #${idx + 1}: ${chain.title}`)} ${chalk.red(`[${chainSev}]`)}`);
            if (chain.findingIds && chain.findingIds.length > 0) {
              console.log(`     ${chalk.gray('Rules:')} ${chalk.cyan(chain.findingIds.join(' + '))}`);
            }
            console.log(`     ${chalk.italic.white(chain.description)}`);
          }
          console.log('');
        }
      }

      if (options.report !== false) {
        const { filePath, format } = resolveReportTarget(
          typeof options.output === 'string' ? options.output : null,
          normalizedFormat
        );

        let reportContent = '';
        if (format === 'json') {
          reportContent = generateJsonReport(report);
          await fs.mkdir(path.dirname(filePath), { recursive: true });
          await fs.writeFile(filePath, reportContent, 'utf-8');
          const displayPath = path.relative(process.cwd(), filePath) || filePath;
          console.log(chalk.cyan(` 📄 Full report saved: ${chalk.bold.underline(displayPath)}\n`));
        } else if (format === 'sarif') {
          reportContent = JSON.stringify(toSarif(report), null, 2);
          await fs.mkdir(path.dirname(filePath), { recursive: true });
          await fs.writeFile(filePath, reportContent, 'utf-8');
          const displayPath = path.relative(process.cwd(), filePath) || filePath;
          console.log(chalk.cyan(` 📄 Full report saved: ${chalk.bold.underline(displayPath)}\n`));
        } else if (format === 'html') {
          reportContent = generateHtmlReport(report);
          await fs.mkdir(path.dirname(filePath), { recursive: true });
          await fs.writeFile(filePath, reportContent, 'utf-8');
          const displayPath = path.relative(process.cwd(), filePath) || filePath;
          console.log(chalk.cyan(` 🌐 Interactive HTML report saved: ${chalk.bold.underline(displayPath)}\n`));
        } else {
          // Default: generate BOTH markdown and interactive HTML!
          reportContent = generateMarkdownReport(report);
          await fs.mkdir(path.dirname(filePath), { recursive: true });
          await fs.writeFile(filePath, reportContent, 'utf-8');
          const displayMdPath = path.relative(process.cwd(), filePath) || filePath;
          console.log(chalk.cyan(` 📄 Full report saved: ${chalk.bold.underline(displayMdPath)}`));

          const htmlFilePath = filePath.replace(/\.(?:md|markdown)$/i, '.html');
          const htmlContent = generateHtmlReport(report);
          await fs.writeFile(htmlFilePath, htmlContent, 'utf-8');
          const displayHtmlPath = path.relative(process.cwd(), htmlFilePath) || htmlFilePath;
          console.log(chalk.cyan(` 🌐 Interactive HTML report saved: ${chalk.bold.underline(displayHtmlPath)}\n`));
        }
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
      if (spinner.isSpinning) {
        spinner.stop();
      }
      console.error(chalk.red(`\n ❌ Scan failed: ${err.message}\n`));
      process.exit(2);
    }
  });

/**
 * Normalizes CLI arguments to support ergonomics and prevent common user typos (e.g. -ai -> --ai).
 *
 * @param {string[]} argv
 * @returns {string[]}
 */
function normalizeCliArgs(argv) {
  if (!Array.isArray(argv)) return argv;
  return argv.map(arg => {
    if (arg === '-ai') return '--ai';
    return arg;
  });
}

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
  program.parse(normalizeCliArgs(process.argv));
}

export { program, generateMarkdownReport, generateHtmlReport, normalizeCliArgs };
