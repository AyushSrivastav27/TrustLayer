import { glob } from 'glob';
import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_IGNORE = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/*.test.js',
  '**/*.spec.js'
];

/**
 * Discovers scannable JavaScript files in the target directory or path.
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

  const ignore = [...DEFAULT_IGNORE, ...(options.ignore || [])];

  const files = await glob('**/*.{js,mjs,cjs}', {
    cwd: resolvedPath,
    absolute: true,
    nodir: true,
    ignore
  });

  return files;
}
