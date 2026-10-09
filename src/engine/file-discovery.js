import { glob } from 'glob';
import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_IGNORE = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/*.test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}',
  '**/*.spec.{js,mjs,cjs,ts,mts,cts,jsx,tsx}',
  '**/*.test.js',
  '**/*.spec.js',
  '**/*.d.ts',
  '**/*.d.mts',
  '**/*.d.cts'
];

/**
 * Discovers scannable JavaScript and TypeScript files in the target directory or path.
 *
 * @param {string} targetPath - Directory or single file path
 * @param {Object} [options]
 * @param {string[]} [options.ignore] - Additional glob ignore patterns
 * @returns {Promise<string[]>} List of absolute file paths
 */
export async function discoverFiles(targetPath, options = {}) {
  const resolvedPath = path.resolve(targetPath);

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Target path does not exist: ${resolvedPath}`);
  }

  if (fs.statSync(resolvedPath).isFile()) {
    return [resolvedPath];
  }

  let fileIgnores = [];
  const ignoreFilePath = path.join(resolvedPath, '.trustlayerignore');
  if (fs.existsSync(ignoreFilePath)) {
    try {
      const content = fs.readFileSync(ignoreFilePath, 'utf-8');
      fileIgnores = content
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'));
    } catch {
      // ignore read failures
    }
  }

  const ignore = [...DEFAULT_IGNORE, ...fileIgnores, ...(options.ignore || [])];

  const files = await glob('**/*.{js,mjs,cjs,ts,mts,cts,jsx,tsx}', {
    cwd: resolvedPath,
    absolute: true,
    nodir: true,
    follow: false,
    ignore
  });

  const maxFileSize = typeof options.maxFileSize === 'number' ? options.maxFileSize : 2 * 1024 * 1024;
  const validFiles = [];

  for (const file of files) {
    try {
      const stat = fs.statSync(file);
      if (stat.size <= maxFileSize) {
        validFiles.push(file);
      } else {
        console.warn(`[TrustLayer] Skipping file exceeding size limit (${(stat.size / (1024 * 1024)).toFixed(2)}MB > ${(maxFileSize / (1024 * 1024)).toFixed(0)}MB): ${file}`);
      }
    } catch {
      // ignore stat errors
    }
  }

  return validFiles;
}
