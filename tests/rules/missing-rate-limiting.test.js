import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/missing-rate-limiting.js';
import { parseSource } from '../../src/engine/ast-parser.js';

function createTestContext(sourceCode, filePath = 'src/routes/auth.js') {
  const { ast } = parseSource(sourceCode, filePath);
  return {
    filePath,
    fileContent: sourceCode,
    ast,
    lines: sourceCode.split('\n')
  };
}

describe('Rule: auth/missing-rate-limiting', () => {
  describe('Rule Metadata', () => {
    it('adheres to Rule contract specifications', () => {
      expect(rule.id).toBe('auth/missing-rate-limiting');
      expect(rule.name).toBeDefined();
      expect(rule.severity).toBe('medium');
      expect(rule.category).toBe('auth');
      expect(typeof rule.analyze).toBe('function');
      expect(rule.defaultExplanation).toBeDefined();
      expect(rule.defaultRemediation).toBeDefined();
    });
  });

  describe('True Positives (Vulnerabilities Detected)', () => {
    it('detects sensitive login route lacking rate limiter', () => {
      const code = `
        router.post('/login', (req, res) => {
          res.json({ token: 'abc' });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('auth/missing-rate-limiting');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].message).toContain('lacks rate limiting middleware');
    });

    it('detects sensitive register route lacking rate limiter', () => {
      const code = `
        router.post('/register', (req, res) => {
          res.json({ ok: true });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(1);
    });

    it('detects unthrottled checkout endpoint in routes/checkout.js', () => {
      const code = `
        router.post('/charge', (req, res) => {
          res.json({ status: 'charged' });
        });
      `;
      const findings = rule.analyze(createTestContext(code, 'src/routes/checkout.js'));
      expect(findings).toHaveLength(1);
    });
  });

  describe('True Negatives (Safe Implementations)', () => {
    it('does not flag route with route-level rate limiting middleware', () => {
      const code = `
        router.post('/login', authLimiter, (req, res) => {
          res.json({ token: 'abc' });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(0);
    });

    it('does not flag route when router has router.use(rateLimiter)', () => {
      const code = `
        router.use(rateLimiter);
        router.post('/login', (req, res) => {
          res.json({ token: 'abc' });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(0);
    });

    it('does not flag route when app has app.use(limiter)', () => {
      const code = `
        app.use(limiter);
        app.post('/login', (req, res) => {
          res.json({ token: 'abc' });
        });
      `;
      const findings = rule.analyze(createTestContext(code, 'src/server.js'));
      expect(findings).toHaveLength(0);
    });

    it('does not flag non-sensitive public read endpoints', () => {
      const code = `
        router.get('/products', (req, res) => {
          res.json({ items: [] });
        });
      `;
      const findings = rule.analyze(createTestContext(code, 'src/routes/products.js'));
      expect(findings).toHaveLength(0);
    });
  });

  describe('Edge Cases & Defensive Handling', () => {
    it('handles null AST gracefully', () => {
      const findings = rule.analyze({ filePath: 'file.txt', fileContent: '', ast: null, lines: [] });
      expect(findings).toEqual([]);
    });

    it('handles empty files or non-Express method calls', () => {
      const code = `
        const arr = [1, 2, 3];
        arr.push(4);
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toEqual([]);
    });
  });
});
