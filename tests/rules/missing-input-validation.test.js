import { describe, it, expect } from 'vitest';
import { parseSource } from '../../src/engine/ast-parser.js';
import missingInputValidationRule from '../../src/rules/missing-input-validation.js';

function analyzeCode(code) {
  const { ast } = parseSource(code, 'test.js');
  const context = {
    filePath: 'test.js',
    fileContent: code,
    ast,
    lines: code.split('\n')
  };
  return missingInputValidationRule.analyze(context);
}

describe('Missing Input Validation Rule', () => {
  it('True Positive: detects req.body access without validation', () => {
    const code = `
      app.post('/api/users', (req, res) => {
        const userId = req.body.userId;
        db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
        res.send('ok');
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('injection/missing-input-validation');
    expect(findings[0].severity).toBe('high');
  });

  it('True Negative: ignores req.body access when zod parse is used', () => {
    const code = `
      app.post('/api/users', (req, res) => {
        const data = schema.parse(req.body);
        db.query(\`SELECT * FROM users WHERE id = \${data.userId}\`);
        res.send('ok');
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('True Negative: ignores when validation middleware is used', () => {
    const code = `
      app.post('/api/users', validate(schema), (req, res) => {
        const userId = req.body.userId;
        res.send('ok');
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('True Negative: ignores when validationResult is used', () => {
    const code = `
      app.post('/api/users', (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json(errors.array());
        const userId = req.body.userId;
        res.send('ok');
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('True Negative: ignores when manual if guard check is used', () => {
    const code = `
      app.post('/api/users', (req, res) => {
        if (!req.body.userId) {
          return res.status(400).send('User ID required');
        }
        res.send('ok');
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('True Negative: ignores when typeof check is used', () => {
    const code = `
      app.post('/api/users', (req, res) => {
        if (typeof req.body.userId !== 'string') {
          return res.status(400).send('Invalid user ID');
        }
        res.send('ok');
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('Edge Case: handles arrow functions without body correctly', () => {
    const code = `
      app.get('/api/health', (req, res) => res.send(req.query.status));
    `;
    const findings = analyzeCode(code);
    // Even though there's no explicit block body, our traverse inside the handler should still work.
    expect(findings).toHaveLength(1);
  });
});
