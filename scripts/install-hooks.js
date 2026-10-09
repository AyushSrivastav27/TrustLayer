import fs from 'node:fs';
import path from 'node:path';

const projectRoot = process.cwd();
const gitHooksDir = path.join(projectRoot, '.git', 'hooks');
const targetHook = path.join(gitHooksDir, 'pre-commit');
const sourceHook = path.join(projectRoot, 'scripts', 'pre-commit.sh');

if (!fs.existsSync(gitHooksDir)) {
  console.error('❌ .git directory not found. Please run within a git repository.');
  process.exit(1);
}

if (!fs.existsSync(sourceHook)) {
  console.error(`❌ Source hook not found at: ${sourceHook}`);
  process.exit(1);
}

try {
  fs.copyFileSync(sourceHook, targetHook);
  fs.chmodSync(targetHook, 0o755);
  console.log('✅ [TrustLayer] Git pre-commit hook installed successfully into .git/hooks/pre-commit');
} catch (err) {
  console.error('❌ Failed to install pre-commit hook:', err.message);
  process.exit(1);
}
