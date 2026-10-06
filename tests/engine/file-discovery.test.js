import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { discoverFiles } from '../../src/engine/file-discovery.js';

describe('Engine: file-discovery (discoverFiles)', () => {
  let tempDir;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustlayer-discovery-'));

    // Create a mock project structure
    // Valid scannable files
    await fs.writeFile(path.join(tempDir, 'index.js'), 'console.log("main");');
    await fs.writeFile(path.join(tempDir, 'module.mjs'), 'export const x = 1;');
    await fs.writeFile(path.join(tempDir, 'common.cjs'), 'module.exports = {};');

    // Nested directory with scannable file
    const nestedDir = path.join(tempDir, 'src', 'controllers');
    await fs.mkdir(nestedDir, { recursive: true });
    await fs.writeFile(path.join(nestedDir, 'user.js'), 'export function user() {}');

    // Default ignored files/folders
    const nodeModulesDir = path.join(tempDir, 'node_modules', 'pkg');
    await fs.mkdir(nodeModulesDir, { recursive: true });
    await fs.writeFile(path.join(nodeModulesDir, 'index.js'), 'module.exports = 1;');

    const gitDir = path.join(tempDir, '.git', 'hooks');
    await fs.mkdir(gitDir, { recursive: true });
    await fs.writeFile(path.join(gitDir, 'pre-commit.js'), '// git hook');

    const distDir = path.join(tempDir, 'dist');
    await fs.mkdir(distDir, { recursive: true });
    await fs.writeFile(path.join(distDir, 'bundle.js'), '// bundle');

    const buildDir = path.join(tempDir, 'build');
    await fs.mkdir(buildDir, { recursive: true });
    await fs.writeFile(path.join(buildDir, 'output.js'), '// output');

    const coverageDir = path.join(tempDir, 'coverage');
    await fs.mkdir(coverageDir, { recursive: true });
    await fs.writeFile(path.join(coverageDir, 'report.js'), '// coverage');

    // Test files (should be ignored by default)
    await fs.writeFile(path.join(tempDir, 'index.test.js'), '// test');
    await fs.writeFile(path.join(tempDir, 'app.spec.js'), '// spec');

    // Non-JS files (should be ignored)
    await fs.writeFile(path.join(tempDir, 'README.md'), '# Readme');
    await fs.writeFile(path.join(tempDir, 'config.json'), '{}');

    // Custom folder to test custom ignore option
    const customDir = path.join(tempDir, 'vendor');
    await fs.mkdir(customDir, { recursive: true });
    await fs.writeFile(path.join(customDir, 'third-party.js'), '// vendor');
  });

  afterAll(async () => {
    if (tempDir) {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('returns a single resolved file path when target is a single file', async () => {
    const singleFile = path.join(tempDir, 'index.js');
    const files = await discoverFiles(singleFile);

    expect(files).toHaveLength(1);
    expect(files[0]).toBe(path.resolve(singleFile));
  });

  it('discovers .js, .mjs, and .cjs files recursively in a directory', async () => {
    const files = await discoverFiles(tempDir);
    const relativePaths = files.map(f => path.relative(tempDir, f).replace(/\\/g, '/'));

    expect(relativePaths).toContain('index.js');
    expect(relativePaths).toContain('module.mjs');
    expect(relativePaths).toContain('common.cjs');
    expect(relativePaths).toContain('src/controllers/user.js');
    expect(relativePaths).toContain('vendor/third-party.js');
  });

  it('ignores default excluded folders (node_modules, .git, dist, build, coverage)', async () => {
    const files = await discoverFiles(tempDir);
    const relativePaths = files.map(f => path.relative(tempDir, f).replace(/\\/g, '/'));

    expect(relativePaths.some(p => p.startsWith('node_modules'))).toBe(false);
    expect(relativePaths.some(p => p.startsWith('.git'))).toBe(false);
    expect(relativePaths.some(p => p.startsWith('dist'))).toBe(false);
    expect(relativePaths.some(p => p.startsWith('build'))).toBe(false);
    expect(relativePaths.some(p => p.startsWith('coverage'))).toBe(false);
  });

  it('ignores test and spec files by default', async () => {
    const files = await discoverFiles(tempDir);
    const relativePaths = files.map(f => path.relative(tempDir, f).replace(/\\/g, '/'));

    expect(relativePaths).not.toContain('index.test.js');
    expect(relativePaths).not.toContain('app.spec.js');
  });

  it('ignores non-JavaScript files (.md, .json)', async () => {
    const files = await discoverFiles(tempDir);
    const relativePaths = files.map(f => path.relative(tempDir, f).replace(/\\/g, '/'));

    expect(relativePaths).not.toContain('README.md');
    expect(relativePaths).not.toContain('config.json');
  });

  it('respects additional custom ignore patterns in options.ignore', async () => {
    const files = await discoverFiles(tempDir, {
      ignore: ['**/vendor/**']
    });
    const relativePaths = files.map(f => path.relative(tempDir, f).replace(/\\/g, '/'));

    expect(relativePaths).toContain('index.js');
    expect(relativePaths).not.toContain('vendor/third-party.js');
  });

  it('always returns absolute paths', async () => {
    const files = await discoverFiles(tempDir);

    for (const file of files) {
      expect(path.isAbsolute(file)).toBe(true);
    }
  });

  it('returns an empty array when directory contains no matching files', async () => {
    const emptySubDir = path.join(tempDir, 'empty-dir');
    await fs.mkdir(emptySubDir, { recursive: true });

    const files = await discoverFiles(emptySubDir);
    expect(files).toEqual([]);
  });
});
