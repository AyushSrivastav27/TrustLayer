import { describe, it, expect } from 'vitest';
import { parseSource } from '../../src/engine/ast-parser.js';
import sqlInjectionRule from '../../src/rules/sql-injection.js';

function analyzeCode(code) {
  const { ast } = parseSource(code, 'test.js');
  const context = {
    filePath: 'test.js',
    fileContent: code,
    ast,
    lines: code.split('\n')
  };
  return sqlInjectionRule.analyze(context);
}

describe('SQL Injection Rule', () => {
  it('True Positive: detects template literal with expressions in db.query', () => {
    const code = `
      const userId = req.body.userId;
      db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('injection/sql-injection');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('template literal');
  });

  it('True Positive: detects string concatenation in db.run', () => {
    const code = `
      const username = req.body.username;
      db.run('SELECT * FROM users WHERE username = ' + username);
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('injection/sql-injection');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('string concatenation');
  });

  it('True Negative: ignores template literals without expressions', () => {
    const code = `
      db.query(\`SELECT * FROM users WHERE id = ?\`, [userId]);
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('True Negative: ignores parameterized queries', () => {
    const code = `
      db.query('SELECT * FROM users WHERE id = $1', [userId]);
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('Edge Case: handles empty db query call gracefully', () => {
    const code = `
      db.query();
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });
});
