import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/idor-access-control.js';
import { parseSource } from '../../src/engine/ast-parser.js';

function createTestContext(sourceCode, filePath = 'src/routes/orders.js') {
  const { ast } = parseSource(sourceCode, filePath);
  return {
    filePath,
    fileContent: sourceCode,
    ast,
    lines: sourceCode.split('\n')
  };
}

describe('Rule: auth/idor-access-control', () => {
  describe('Rule Metadata', () => {
    it('adheres to Rule contract specifications', () => {
      expect(rule.id).toBe('auth/idor-access-control');
      expect(rule.name).toBeDefined();
      expect(rule.severity).toBe('high');
      expect(rule.category).toBe('auth');
      expect(typeof rule.analyze).toBe('function');
      expect(rule.defaultExplanation).toBeDefined();
      expect(rule.defaultRemediation).toBeDefined();
    });
  });

  describe('True Positives (Vulnerabilities Detected)', () => {
    it('detects un-scoped database lookup using req.params.id', () => {
      const code = `
        router.get('/orders/:id', (req, res) => {
          const orderId = req.params.id;
          const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
          res.json({ order });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('auth/idor-access-control');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].message).toContain('IDOR/BOLA');
    });

    it('detects destructured id from req.params in database query without owner scoping', () => {
      const code = `
        router.get('/invoices/:id', (req, res) => {
          const { id } = req.params;
          const invoice = db.query('SELECT * FROM invoices WHERE id = $1', [id]);
          res.json({ invoice });
        });
      `;
      const findings = rule.analyze(createTestContext(code, 'src/routes/invoices.js'));
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('auth/idor-access-control');
    });

    it('detects Model.findById with req.params.id lacking ownership check', () => {
      const code = `
        router.get('/account/:id', async (req, res) => {
          const account = await Account.findById(req.params.id);
          res.json(account);
        });
      `;
      const findings = rule.analyze(createTestContext(code, 'src/routes/account.js'));
      expect(findings).toHaveLength(1);
    });
  });

  describe('True Negatives (Safe Implementations)', () => {
    it('does not flag query scoped with user_id and req.user.id', () => {
      const code = `
        router.get('/orders/:id', (req, res) => {
          const orderId = req.params.id;
          const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get([orderId, req.user.id]);
          res.json({ order });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(0);
    });

    it('does not flag when explicit ownership check is performed in handler body', () => {
      const code = `
        router.get('/orders/:id', (req, res) => {
          const orderId = req.params.id;
          const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
          if (order.userId !== req.user.id) {
            return res.status(403).json({ error: 'Forbidden' });
          }
          res.json({ order });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(0);
    });

    it('does not flag when ownership guard helper is invoked', () => {
      const code = `
        router.get('/orders/:id', (req, res) => {
          const orderId = req.params.id;
          const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
          checkOwnership(order, req.user.id);
          res.json({ order });
        });
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toHaveLength(0);
    });

    it('does not flag public catalog endpoints like products.js', () => {
      const code = `
        router.get('/:id', (req, res) => {
          const productId = req.params.id;
          const product = db.prepare('SELECT * FROM products WHERE id = ?').get(productId);
          res.json({ product });
        });
      `;
      const findings = rule.analyze(createTestContext(code, 'src/routes/products.js'));
      expect(findings).toHaveLength(0);
    });
  });

  describe('Edge Cases & Defensive Handling', () => {
    it('handles null AST or non-js context gracefully', () => {
      const findings = rule.analyze({ filePath: 'unknown.txt', fileContent: '', ast: null, lines: [] });
      expect(findings).toEqual([]);
    });

    it('handles empty handlers and non-Express calls without errors', () => {
      const code = `
        router.get('/empty');
        const x = Math.random();
        db.query();
      `;
      const findings = rule.analyze(createTestContext(code));
      expect(findings).toEqual([]);
    });
  });
});
