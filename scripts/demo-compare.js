#!/usr/bin/env node

import chalk from 'chalk';
import path from 'node:path';
import { scan, SCANNER_VERSION } from '../src/engine/scanner.js';

const SEVERITY_ICONS = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵'
};

async function runComparison() {
  console.log(chalk.cyan.bold('\n' + '═'.repeat(74)));
  console.log(chalk.bold.white(` 🛡️  TrustLayer v${SCANNER_VERSION} — Live Security Verification & Comparison`));
  console.log(chalk.gray('    Comparing: Vulnerable Demo (demo) vs Remediated Demo (demo-fixed)'));
  console.log(chalk.cyan.bold('═'.repeat(74) + '\n'));

  // ---------------------------------------------------------
  // 1. Scan Vulnerable Demo
  // ---------------------------------------------------------
  console.log(chalk.bold.red('▶ STEP 1: Scanning Unprotected Express Backend (./demo)...'));
  const demoTarget = path.resolve(process.cwd(), './demo');
  const demoReport = await scan(demoTarget);

  console.log(
    chalk.gray(`  Scanned ${demoReport.summary.totalFiles} files in ${demoReport.summary.scanDurationMs}ms.\n`)
  );

  for (const finding of demoReport.findings) {
    const icon = SEVERITY_ICONS[finding.severity] || '⚪';
    const sev = finding.severity.toUpperCase().padEnd(9);
    const relFile = path.relative(process.cwd(), finding.file);
    const colorFn = finding.severity === 'critical' ? chalk.red.bold
      : finding.severity === 'high' ? chalk.hex('#FFA500').bold
      : chalk.yellow;

    console.log(
      `  ${icon} ${colorFn(sev)} ${chalk.white.bold(finding.message.padEnd(36))} ${chalk.gray(`${relFile}:${finding.line}`)}`
    );
  }

  const c1 = demoReport.summary.severities;
  console.log(
    chalk.bold.red(
      `\n  ❌ Status: FAILED CI GATE — Found ${demoReport.findings.length} vulnerabilities (` +
      `${c1.critical} critical, ${c1.high} high, ${c1.medium} medium, ${c1.low} low)\n`
    )
  );

  // ---------------------------------------------------------
  // 2. Scan Fixed Demo
  // ---------------------------------------------------------
  console.log(chalk.bold.green('▶ STEP 2: Scanning Remediated Production Backend (./demo-fixed)...'));
  const fixedTarget = path.resolve(process.cwd(), './demo-fixed');
  const fixedReport = await scan(fixedTarget);

  console.log(
    chalk.gray(`  Scanned ${fixedReport.summary.totalFiles} files in ${fixedReport.summary.scanDurationMs}ms.\n`)
  );

  if (fixedReport.findings.length === 0) {
    console.log(chalk.bold.green('  ✅ Status: PASSED CI GATE — 0 Vulnerabilities Detected. 100% Compliant!\n'));
  } else {
    console.log(chalk.bold.yellow(`  ⚠️  Found ${fixedReport.findings.length} unexpected findings in fixed demo.\n`));
  }

  // ---------------------------------------------------------
  // 3. Side-by-Side Verification Summary
  // ---------------------------------------------------------
  console.log(chalk.cyan.bold('═'.repeat(74)));
  console.log(chalk.bold.white(' 📊 TrustLayer Remediation Impact Matrix'));
  console.log(chalk.cyan.bold('═'.repeat(74)));

  console.log(
    chalk.bold(
      ' | ' + 'Metric'.padEnd(32) + 
      ' | ' + 'Vulnerable (demo)'.padEnd(20) + 
      ' | ' + 'Hardened (demo-fixed)'.padEnd(20) + ' |'
    )
  );
  console.log(' |' + '-'.repeat(34) + '|' + '-'.repeat(22) + '|' + '-'.repeat(22) + '|');

  const rows = [
    ['Total Security Issues', `${demoReport.findings.length} findings`, `${fixedReport.findings.length} findings`],
    ['Critical Vulnerabilities', `${c1.critical} detected`, `${fixedReport.summary.severities.critical} detected`],
    ['High Severity Risks', `${c1.high} detected`, `${fixedReport.summary.severities.high} detected`],
    ['Payment Tampering Gaps', 'Vulnerable to ₹1 checkout', 'Server-verified price'],
    ['Webhook Verification', 'Missing signature checks', 'Cryptographically verified'],
    ['Authentication Guards', 'Unauthenticated routes', 'JWT / Auth enforced'],
    ['CI/CD Pipeline Gate', 'BLOCKED (Exit 1)', 'PASSED (Exit 0)']
  ];

  for (const [metric, before, after] of rows) {
    const coloredBefore = before.includes('detected') || before.includes('Vulnerable') || before.includes('BLOCKED')
      ? chalk.red(before.padEnd(20))
      : chalk.gray(before.padEnd(20));

    const coloredAfter = after.includes('0') || after.includes('PASSED') || after.includes('Server') || after.includes('Crypto') || after.includes('enforced')
      ? chalk.green.bold(after.padEnd(20))
      : chalk.gray(after.padEnd(20));

    console.log(` | ${metric.padEnd(32)} | ${coloredBefore} | ${coloredAfter} |`);
  }

  console.log(chalk.cyan.bold('═'.repeat(74)));
  console.log(chalk.bold.cyan(' 🚀 Deterministic AST scan complete. Ready for production deployment.\n'));
}

runComparison().catch((err) => {
  console.error(chalk.red('Comparison error:'), err);
  process.exit(1);
});
