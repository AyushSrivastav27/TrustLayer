import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { discoverFiles, DEFAULT_MAX_FILE_SIZE } from '../../src/engine/file-discovery.js';

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

    // TypeScript and JSX scannable files
    await fs.writeFile(path.join(tempDir, 'service.ts'), 'export const s = 2;');
    await fs.writeFile(path.join(tempDir, 'component.tsx'), 'export const c = () => null;');
    await fs.writeFile(path.join(tempDir, 'types.d.ts'), 'declare const d: number;');
    await fs.writeFile(path.join(tempDir, 'service.test.ts'), '// test ts');

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

  it('throws an error when targetPath does not exist', async () => {
    const nonExistent = path.join(tempDir, 'non-existent-path');
    await expect(discoverFiles(nonExistent)).rejects.toThrow('Target path does not exist');
  });

  it('discovers TypeScript (.ts, .tsx) files while ignoring .d.ts and test files', async () => {
    const files = await discoverFiles(tempDir);
    const relativePaths = files.map(f => path.relative(tempDir, f).replace(/\\/g, '/'));

    expect(relativePaths).toContain('service.ts');
    expect(relativePaths).toContain('component.tsx');
    expect(relativePaths).not.toContain('types.d.ts');
    expect(relativePaths).not.toContain('service.test.ts');
  });

  it('respects .trustlayerignore file in target directory', async () => {
    const ignoreDir = path.join(tempDir, 'ignore-test-project');
    await fs.mkdir(path.join(ignoreDir, 'legacy'), { recursive: true });
    await fs.writeFile(path.join(ignoreDir, 'app.js'), '// app');
    await fs.writeFile(path.join(ignoreDir, 'legacy', 'old.js'), '// old');
    await fs.writeFile(path.join(ignoreDir, '.trustlayerignore'), '# comments\n**/legacy/**\n');

    const files = await discoverFiles(ignoreDir);
    const relativePaths = files.map(f => path.relative(ignoreDir, f).replace(/\\/g, '/'));

    expect(relativePaths).toContain('app.js');
    expect(relativePaths).not.toContain('legacy/old.js');
  });

  describe('Scanner Self-Defense & Input Hygiene', () => {
    it('exports DEFAULT_MAX_FILE_SIZE as 2MB (2097152 bytes)', () => {
      expect(DEFAULT_MAX_FILE_SIZE).toBe(2 * 1024 * 1024);
    });

    it('skips files exceeding maxFileSize limit (default 2MB)', async () => {
      const largeFileDir = path.join(tempDir, 'large-file-test');
      await fs.mkdir(largeFileDir, { recursive: true });

      // Create a 2.5MB file
      const bigFilePath = path.join(largeFileDir, 'bundle.js');
      const normalFilePath = path.join(largeFileDir, 'small.js');

      const largeBuffer = Buffer.alloc(2.5 * 1024 * 1024, 'a');
      await fs.writeFile(bigFilePath, largeBuffer);
      await fs.writeFile(normalFilePath, 'console.log("ok");');

      const discovered = await discoverFiles(largeFileDir);
      const relative = discovered.map(f => path.relative(largeFileDir, f).replace(/\\/g, '/'));

      expect(relative).toContain('small.js');
      expect(relative).not.toContain('bundle.js');
    });

    it('allows overriding maxFileSize in options', async () => {
      const customSizeDir = path.join(tempDir, 'custom-size-test');
      await fs.mkdir(customSizeDir, { recursive: true });

      const file500b = path.join(customSizeDir, 'medium.js');
      await fs.writeFile(file500b, 'a'.repeat(500));

      // With maxFileSize of 100 bytes, medium.js should be excluded
      const discoveredSmallLimit = await discoverFiles(customSizeDir, { maxFileSize: 100 });
      expect(discoveredSmallLimit).toHaveLength(0);

      // With maxFileSize of 1000 bytes, medium.js should be included
      const discoveredLargeLimit = await discoverFiles(customSizeDir, { maxFileSize: 1000 });
      expect(discoveredLargeLimit).toHaveLength(1);
    });

    it('prevents infinite recursion on circular directory symlinks by defaulting to follow: false', async () => {
      const symlinkDir = path.join(tempDir, 'symlink-test');
      await fs.mkdir(symlinkDir, { recursive: true });
      await fs.writeFile(path.join(symlinkDir, 'entry.js'), 'export const a = 1;');

      // Create cyclic symlink: symlink-test/loop -> symlink-test
      try {
        await fs.symlink(symlinkDir, path.join(symlinkDir, 'loop'), 'dir');
      } catch {
        // In case system permissions prevent symlink creation, skip test assertion gracefully
        return;
      }

      // Should complete quickly without infinite loop
      const startTime = Date.now();
      const files = await discoverFiles(symlinkDir);
      const elapsed = Date.now() - startTime;

      expect(elapsed).toBeLessThan(1000);
      expect(files.some(f => f.endsWith('entry.js'))).toBe(true);
    });

    it('gracefully handles broken symlinks without crashing', async () => {
      const brokenDir = path.join(tempDir, 'broken-symlink-test');
      await fs.mkdir(brokenDir, { recursive: true });
      await fs.writeFile(path.join(brokenDir, 'valid.js'), 'console.log("valid");');

      try {
        await fs.symlink(path.join(brokenDir, 'does-not-exist.js'), path.join(brokenDir, 'ghost.js'));
      } catch {
        return;
      }

      const files = await discoverFiles(brokenDir);
      const relative = files.map(f => path.relative(brokenDir, f).replace(/\\/g, '/'));

      expect(relative).toContain('valid.js');
      expect(relative).not.toContain('ghost.js');
    });
  });
});


