import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolveReportTarget, generateMarkdownReport, normalizeCliArgs } from '../src/cli.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const CLI_PATH = path.resolve(REPO_ROOT, 'src/cli.js');

function runCli(args = [], customEnv = {}) {
  return new Promise((resolve) => {
    execFile(
      'node',
      [CLI_PATH, ...args],
      {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          GEMINI_API_KEY: '',
          GOOGLE_API_KEY: '',
          ANTHROPIC_API_KEY: '',
          CLAUDE_API_KEY: '',
          OPENAI_API_KEY: '',
          ...customEnv
        }
      },
      (error, stdout, stderr) => {
        resolve({
          code: error ? (error.code ?? 1) : 0,
          stdout: stdout || '',
          stderr: stderr || '',
          error
        });
      }
    );
  });
}

describe('CLI: resolveReportTarget unit tests', () => {
  it('returns default SECURITY-REPORT.md when outputOption is null and format is markdown', () => {
    const result = resolveReportTarget(null, 'markdown');
    expect(result.format).toBe('markdown');
    expect(result.filePath).toBe(path.resolve(process.cwd(), 'SECURITY-REPORT.md'));
  });

  it('returns default security-report.json when outputOption is null and format is json', () => {
    const result = resolveReportTarget(null, 'json');
    expect(result.format).toBe('json');
    expect(result.filePath).toBe(path.resolve(process.cwd(), 'security-report.json'));
  });

  it('normalizes md format alias to markdown', () => {
    const result = resolveReportTarget(null, 'md');
    expect(result.format).toBe('markdown');
    expect(result.filePath).toBe(path.resolve(process.cwd(), 'SECURITY-REPORT.md'));
  });

  it('appends .md when path has no extension and format is markdown', () => {
    const result = resolveReportTarget('my-report', 'markdown');
    expect(result.format).toBe('markdown');
    expect(result.filePath).toBe(path.resolve(process.cwd(), 'my-report.md'));
  });

  it('appends .json when path has no extension and format is json', () => {
    const result = resolveReportTarget('audit', 'json');
    expect(result.format).toBe('json');
    expect(result.filePath).toBe(path.resolve(process.cwd(), 'audit.json'));
  });

  it('overrides format to json if outputOption filename ends with .json', () => {
    const result = resolveReportTarget('custom-output.json', 'markdown');
    expect(result.format).toBe('json');
    expect(result.filePath).toBe(path.resolve(process.cwd(), 'custom-output.json'));
  });

  it('overrides format to markdown if outputOption filename ends with .md or .markdown', () => {
    const mdResult = resolveReportTarget('custom-output.md', 'json');
    expect(mdResult.format).toBe('markdown');
    expect(mdResult.filePath).toBe(path.resolve(process.cwd(), 'custom-output.md'));

    const markdownResult = resolveReportTarget('custom-output.markdown', 'json');
    expect(markdownResult.format).toBe('markdown');
    expect(markdownResult.filePath).toBe(path.resolve(process.cwd(), 'custom-output.markdown'));
  });

  it('trims whitespace from output option', () => {
    const result = resolveReportTarget('   custom/path.json   ', 'markdown');
    expect(result.format).toBe('json');
    expect(result.filePath).toBe(path.resolve(process.cwd(), 'custom/path.json'));
  });
});

describe('CLI: normalizeCliArgs unit tests', () => {
  it('converts -ai typo into --ai flag', () => {
    expect(normalizeCliArgs(['node', 'src/cli.js', 'scan', '-ai'])).toEqual([
      'node',
      'src/cli.js',
      'scan',
      '--ai'
    ]);
  });

  it('leaves standard flags untouched', () => {
    expect(normalizeCliArgs(['scan', '-a', '-v', '--ai'])).toEqual([
      'scan',
      '-a',
      '-v',
      '--ai'
    ]);
  });

  it('safely handles non-array inputs', () => {
    expect(normalizeCliArgs(null)).toBeNull();
    expect(normalizeCliArgs(undefined)).toBeUndefined();
  });
});

describe('CLI: generateMarkdownReport integrated reporter unit tests', () => {
  it('generates a clean scan report when there are no findings', () => {
    const report = {
      targetDirectory: '/test/dir',
      scanDate: '2026-10-08T00:00:00.000Z',
      summary: {
        totalFiles: 5,
        totalFindings: 0,
        severities: { critical: 0, high: 0, medium: 0, low: 0 }
      },
      findings: []
    };

    const output = generateMarkdownReport(report);
    expect(output).toContain('TrustLayer Security Audit Report');
    expect(output).toContain('Clean Scan');
    expect(output).toContain('zero security findings');
  });

  it('generates detailed findings list with snippets and remediation when findings exist', () => {
    const report = {
      targetDirectory: '/test/dir',
      scanDate: '2026-10-08T00:00:00.000Z',
      summary: {
        totalFiles: 3,
        totalFindings: 1,
        severities: { critical: 1, high: 0, medium: 0, low: 0 }
      },
      findings: [
        {
          ruleId: 'payment/client-controlled-amount',
          severity: 'critical',
          message: 'Client-controlled payment amount detected',
          file: '/test/dir/checkout.js',
          line: 42,
          confidence: 'high',
          codeSnippet: 'const amount = req.body.amount;',
          explanation: 'Attackers can manipulate the order amount.',
          remediation: 'Fetch the price from the database.'
        }
      ]
    };

    const output = generateMarkdownReport(report);
    expect(output).toContain('CRITICAL');
    expect(output).toContain('Client-controlled payment amount detected');
    expect(output).toContain('payment/client-controlled-amount');
    expect(output).toContain('const amount = req.body.amount;');
    expect(output).toContain('Attackers can manipulate the order amount.');
    expect(output).toContain('Fetch the price from the database.');
  });
});

describe('CLI: Subprocess execution and exit codes', () => {
  let tempDir;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustlayer-cli-test-'));
  });

  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('prints help and exits with 0 on --help', async () => {
    const res = await runCli(['--help']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('trustlayer');
    expect(res.stdout).toContain('Scan target directory or file');
    expect(res.stdout).toContain('Examples:');
  }, 10000);

  it('prints version and exits with 0 on --version', async () => {
    const res = await runCli(['--version']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('1.0.0');
  }, 10000);

  it('exits with code 2 when target path does not exist', async () => {
    const nonExistentPath = path.join(tempDir, 'non-existent-subpath-999');
    const res = await runCli(['scan', nonExistentPath, '--no-banner']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('does not exist');
  }, 10000);

  it('exits with code 2 when unsupported format is provided', async () => {
    const res = await runCli(['scan', 'demo', '-f', 'yaml', '--no-banner']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('Unsupported format "yaml"');
  }, 10000);

  it('exits with code 2 when custom rules directory does not exist', async () => {
    const badRulesDir = path.join(tempDir, 'missing-rules-dir');
    const res = await runCli(['scan', 'demo', '-r', badRulesDir, '--no-banner']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('Custom rules directory');
  }, 10000);

  it('exits with code 0 on clean scan (demo-fixed) with --no-report', async () => {
    const res = await runCli(['scan', 'demo-fixed', '--no-report', '--no-banner']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('No security issues found');
  }, 15000);

  it('exits with code 1 on vulnerable target (demo) due to critical/high findings', async () => {
    const res = await runCli(['scan', 'demo', '--no-report', '--no-banner']);
    expect(res.code).toBe(1);
    expect(res.stdout).toContain('Found');
    expect(res.stdout).toContain('critical');
  }, 15000);

  it('saves report file to disk when requested', async () => {
    const reportPath = path.join(tempDir, 'test-report.json');
    const res = await runCli(['scan', 'demo-fixed', '-o', reportPath, '-f', 'json', '--no-banner']);
    expect(res.code).toBe(0);

    const exists = await fs.stat(reportPath).then(() => true).catch(() => false);
    expect(exists).toBe(true);

    const content = JSON.parse(await fs.readFile(reportPath, 'utf-8'));
    expect(content).toHaveProperty('summary');
    expect(content.summary.totalFindings).toBe(0);
  }, 15000);

  it('exits with code 0 when --fail-on none is used on vulnerable code', async () => {
    const res = await runCli(['scan', 'demo', '--fail-on', 'none', '--no-report', '--no-banner']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('Found');
  }, 15000);

  it('exits with code 2 when an invalid --fail-on value is passed', async () => {
    const res = await runCli(['scan', 'demo', '--fail-on', 'invalid-level', '--no-banner']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('Invalid --fail-on level');
  }, 10000);

  it('filters findings by severity with -s option', async () => {
    // demo has 0 low findings, so filtering to -s low results in 0 findings and exit code 0
    const res = await runCli(['scan', 'demo', '-s', 'low', '--no-report', '--no-banner']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('No security issues found');
  }, 15000);

  it('filters findings by category with -c option', async () => {
    const res = await runCli(['scan', 'demo', '-c', 'payment', '--no-report', '--no-banner']);
    expect(res.stdout).toContain('payment');
  }, 15000);

  it('runs scan with --ai and outputs attack chains', async () => {
    const res = await runCli(['scan', 'demo', '--ai', '--no-report', '--no-banner', '--fail-on', 'none']);
    expect(res.code).toBe(0);
    expect(res.stdout).toMatch(/AI Mode: (🔌 OFFLINE|🌐 ONLINE)/);
    expect(res.stdout).toContain('Correlated Attack Chains');
    expect(res.stdout).toMatch(/\[AI: (Offline|Online)\]/);
  }, 15000);

  it('warns user when --api-key is passed as command-line argument', async () => {
    const res = await runCli(['scan', 'demo-fixed', '--ai', '--api-key', 'AIzaSyFakeTestKey123', '--no-report', '--no-banner']);
    expect(res.code).toBe(0);
    expect(res.stderr + res.stdout).toContain('Warning: Passing API keys via command-line arguments');
    expect(res.stdout).toContain('AI Mode: 🌐 ONLINE');
  }, 15000);

  it('prints detailed remediation and exploit preview in terminal with -v/--verbose', async () => {
    const res = await runCli(['scan', 'demo/routes/checkout.js', '-v', '--ai', '--no-report', '--no-banner', '--fail-on', 'none']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('Fix:');
    expect(res.stdout).toContain('Exploit:');
  }, 30000);

  it('exports valid SARIF document when -f sarif is specified', async () => {
    const sarifPath = path.join(tempDir, 'audit.sarif');
    const res = await runCli(['scan', 'demo-fixed', '-o', sarifPath, '-f', 'sarif', '--no-banner']);
    expect(res.code).toBe(0);

    const exists = await fs.stat(sarifPath).then(() => true).catch(() => false);
    expect(exists).toBe(true);

    const content = JSON.parse(await fs.readFile(sarifPath, 'utf-8'));
    expect(content.version).toBe('2.1.0');
    expect(content.runs[0].tool.driver.name).toBe('TrustLayer');
  }, 15000);

  it('supports shorthand -a flag for AI mode', async () => {
    const res = await runCli(['scan', 'demo', '-a', '--no-report', '--no-banner', '--fail-on', 'none']);
    expect(res.code).toBe(0);
    expect(res.stdout).toMatch(/AI Mode: (🔌 OFFLINE|🌐 ONLINE)/);
    expect(res.stdout).toContain('Correlated Attack Chains');
  }, 15000);

  it('normalizes -ai typo and successfully runs scan in AI mode', async () => {
    const res = await runCli(['scan', 'demo', '-ai', '--no-report', '--no-banner', '--fail-on', 'none']);
    expect(res.code).toBe(0);
    expect(res.stdout).toMatch(/AI Mode: (🔌 OFFLINE|🌐 ONLINE)/);
    expect(res.stdout).toContain('Correlated Attack Chains');
  }, 15000);

  it('supports combined shorthand flags -av (AI mode + verbose)', async () => {
    const res = await runCli(['scan', 'demo/routes/checkout.js', '-av', '--no-report', '--no-banner', '--fail-on', 'none']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('Fix:');
    expect(res.stdout).toContain('Exploit:');
  }, 30000);

  it('exits with code 2 on unknown option syntax error', async () => {
    const res = await runCli(['scan', 'demo', '--non-existent-option-xyz', '--no-banner']);
    expect(res.code).toBe(2);
  }, 10000);

  it('exports valid SARIF document with relative repo paths and driver rules', async () => {
    const sarifPath = path.join(tempDir, 'demo-findings.sarif');
    const res = await runCli(['scan', 'demo', '-o', sarifPath, '-f', 'sarif', '--no-banner', '--fail-on', 'none']);
    expect(res.code).toBe(0);

    const exists = await fs.stat(sarifPath).then(() => true).catch(() => false);
    expect(exists).toBe(true);

    const content = JSON.parse(await fs.readFile(sarifPath, 'utf-8'));
    expect(content.version).toBe('2.1.0');
    expect(content.runs[0].results.length).toBeGreaterThan(0);
    const firstResult = content.runs[0].results[0];
    expect(firstResult.locations[0].physicalLocation.artifactLocation.uri).not.toMatch(/^\//);
    expect(firstResult.locations[0].physicalLocation.artifactLocation.uriBaseId).toBe('%SRCROOT%');
    expect(content.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
    expect(content.runs[0].tool.driver.rules[0]).toHaveProperty('defaultConfiguration');
  }, 15000);
});



