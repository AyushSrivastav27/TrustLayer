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

export const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB

/**
 * Discovers scannable JavaScript and TypeScript files in the target directory or path.
 *
 * @param {string} targetPath - Directory or single file path
 * @param {Object} [options]
 * @param {string[]} [options.ignore] - Additional glob ignore patterns
 * @param {number} [options.maxFileSize] - Maximum allowed file size in bytes (default 2MB)
 * @param {boolean} [options.followSymbolicLinks] - Whether to follow directory symlinks (default false)
 * @returns {Promise<string[]>} List of absolute file paths
 */
export async function discoverFiles(targetPath, options = {}) {
  const resolvedPath = path.resolve(targetPath);

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Target path does not exist: ${resolvedPath}`);
  }

  const maxFileSize = options.maxFileSize !== undefined ? options.maxFileSize : DEFAULT_MAX_FILE_SIZE;
  const followSymbolicLinks = Boolean(options.followSymbolicLinks);

  if (fs.statSync(resolvedPath).isFile()) {
    if (maxFileSize !== null && maxFileSize !== undefined && maxFileSize !== Infinity) {
      const stat = fs.statSync(resolvedPath);
      if (stat.size > maxFileSize) {
        return [];
      }
    }
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
    follow: followSymbolicLinks,
    ignore
  });

  const validFiles = [];
  for (const file of files) {
    try {
      const stat = fs.statSync(file);
      if (!stat.isFile()) continue;
      if (maxFileSize !== null && maxFileSize !== undefined && maxFileSize !== Infinity && stat.size > maxFileSize) {
        continue;
      }
      validFiles.push(file);
    } catch {
      // Skip unreadable files or broken symlinks
    }
  }

  return validFiles;
}
