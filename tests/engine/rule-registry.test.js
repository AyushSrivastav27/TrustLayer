import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { loadRules, VALID_SEVERITIES, VALID_CATEGORIES } from '../../src/engine/rule-registry.js';

describe('Engine: rule-registry (loadRules)', () => {
  let tempRulesDir;

  beforeAll(async () => {
    tempRulesDir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustlayer-rules-'));

    // Valid rule 1
    await fs.writeFile(
      path.join(tempRulesDir, 'rule-one.js'),
      `export default {
        id: 'test/rule-one',
        name: 'Test Rule One',
        severity: 'high',
        category: 'injection',
        description: 'First test rule',
        defaultExplanation: 'Explanation',
        defaultRemediation: 'Remediation',
        analyze(context) { return []; }
      };`
    );

    // Valid rule 2
    await fs.writeFile(
      path.join(tempRulesDir, 'rule-two.js'),
      `export default {
        id: 'test/rule-two',
        name: 'Test Rule Two',
        severity: 'critical',
        category: 'payment',
        description: 'Second test rule',
        defaultExplanation: 'Explanation',
        defaultRemediation: 'Remediation',
        analyze(context) { return []; }
      };`
    );

    // Invalid rule: missing `id`
    await fs.writeFile(
      path.join(tempRulesDir, 'invalid-no-id.js'),
      `export default {
        name: 'Missing ID',
        analyze(context) { return []; }
      };`
    );

    // Invalid rule: missing `analyze` function
    await fs.writeFile(
      path.join(tempRulesDir, 'invalid-no-analyze.js'),
      `export default {
        id: 'test/no-analyze',
        name: 'Missing Analyze'
      };`
    );

    // Invalid rule: export is not an object
    await fs.writeFile(
      path.join(tempRulesDir, 'invalid-not-object.js'),
      `export default "not an object";`
    );

    // Broken rule: syntax error during import
    await fs.writeFile(
      path.join(tempRulesDir, 'broken-syntax.js'),
      `export default { broken syntax ::::`
    );

    // Invalid rule: invalid severity
    await fs.writeFile(
      path.join(tempRulesDir, 'invalid-severity.js'),
      `export default {
        id: 'test/invalid-severity',
        name: 'Invalid Severity',
        severity: 'ultra-critical',
        category: 'secrets',
        analyze(context) { return []; }
      };`
    );

    // Invalid rule: invalid category
    await fs.writeFile(
      path.join(tempRulesDir, 'invalid-category.js'),
      `export default {
        id: 'test/invalid-category',
        name: 'Invalid Category',
        severity: 'critical',
        category: 'networking',
        analyze(context) { return []; }
      };`
    );
  });

  afterAll(async () => {
    if (tempRulesDir) {
      await fs.rm(tempRulesDir, { recursive: true, force: true });
    }
  });

  it('loads valid rules dynamically from a specified directory', async () => {
    // Silence warning for broken-syntax.js during this test
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const rules = await loadRules(tempRulesDir);

    expect(Array.isArray(rules)).toBe(true);
    const ruleIds = rules.map(r => r.id);
    expect(ruleIds).toContain('test/rule-one');
    expect(ruleIds).toContain('test/rule-two');

    warnSpy.mockRestore();
  });

  it('filters out invalid rules that lack id or analyze function', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const rules = await loadRules(tempRulesDir);
    const ruleIds = rules.map(r => r.id);

    // Should only have the 2 valid rules
    expect(rules).toHaveLength(2);
    expect(ruleIds).not.toContain('test/no-analyze');

    warnSpy.mockRestore();
  });

  it('handles load errors gracefully without crashing the engine', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const rules = await loadRules(tempRulesDir);

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to load rule at'),
      expect.any(String)
    );
    expect(Array.isArray(rules)).toBe(true);

    warnSpy.mockRestore();
  });

  it('returns an empty array when rules directory has no .js files', async () => {
    const emptyDir = path.join(tempRulesDir, 'empty-dir');
    await fs.mkdir(emptyDir, { recursive: true });

    const rules = await loadRules(emptyDir);
    expect(rules).toEqual([]);
  });

  it('defaults to src/rules when no rulesDir argument is passed', async () => {
    // Calling loadRules() without arguments should default to process.cwd()/src/rules
    // Currently placeholder files in src/rules exist, so it should return an array without throwing
    const rules = await loadRules();
    expect(Array.isArray(rules)).toBe(true);
  });

  it('exports VALID_SEVERITIES and VALID_CATEGORIES arrays', () => {
    expect(VALID_SEVERITIES).toEqual(['critical', 'high', 'medium', 'low']);
    expect(VALID_CATEGORIES).toEqual(['secrets', 'injection', 'payment', 'auth']);
  });

  it('filters out rules with invalid severity or category and logs validation warnings', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const rules = await loadRules(tempRulesDir);
    const ruleIds = rules.map(r => r.id);

    expect(ruleIds).not.toContain('test/invalid-severity');
    expect(ruleIds).not.toContain('test/invalid-category');
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('failed contract validation')
    );

    warnSpy.mockRestore();
  });
});
