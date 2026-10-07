import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/missing-auth-middleware.js';
import { parseSource } from '../../src/engine/ast-parser.js';

function analyzeCode(code, filePath = 'server.js') {
  const { ast } = parseSource(code, filePath);
  const lines = code.split('\n');
  return rule.analyze({
    filePath,
    fileContent: code,
    ast,
    lines
  });
}

describe('Rule: auth/missing-auth-middleware', () => {
  it('flags sensitive order route lacking auth middleware (true positive)', () => {
    const code = `
      router.get('/api/orders', (req, res) => {
        const orders = db.all('SELECT * FROM orders');
        res.json(orders);
      });
    `;
    const findings = analyzeCode(code, 'routes/orders.js');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('auth/missing-auth-middleware');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].codeSnippet).toContain("'/api/orders'");
  });

  it('flags unauthenticated route inside sensitive route file (routes/orders.js)', () => {
    const code = `
      router.get('/:id', (req, res) => {
        const order = db.get('SELECT * FROM orders WHERE id = ?', [req.params.id]);
        res.json(order);
      });
    `;
    const findings = analyzeCode(code, 'routes/orders.js');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('auth/missing-auth-middleware');
  });

  it('flags checkout route without auth', () => {
    const code = `
      app.post('/api/checkout', (req, res) => {
        res.json({ status: 'processing' });
      });
    `;
    const findings = analyzeCode(code, 'app.js');
    expect(findings).toHaveLength(1);
  });

  it('ignores route protected with requireAuth middleware (true negative)', () => {
    const code = `
      router.get('/api/orders', requireAuth, (req, res) => {
        res.json({ orders: [] });
      });
    `;
    const findings = analyzeCode(code, 'routes/orders.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores route protected with passport.authenticate (true negative)', () => {
    const code = `
      router.get('/api/user/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
        res.json(req.user);
      });
    `;
    const findings = analyzeCode(code, 'routes/user.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores routes when router.use(authenticate) is applied (true negative)', () => {
    const code = `
      router.use(authenticate);

      router.get('/', (req, res) => {
        res.json({ orders: [] });
      });

      router.get('/:id', (req, res) => {
        res.json({ order: req.params.id });
      });
    `;
    const findings = analyzeCode(code, 'routes/orders.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores public routes like products, login, and health checks (whitelist)', () => {
    const code = `
      router.get('/api/products', (req, res) => {
        res.json({ items: [] });
      });

      router.post('/api/login', (req, res) => {
        res.json({ token: 'mock' });
      });

      router.get('/health', (req, res) => {
        res.send('ok');
      });
    `;
    const findings = analyzeCode(code, 'routes/products.js');
    expect(findings).toHaveLength(0);
  });

  it('handles null AST gracefully (edge case)', () => {
    const findings = rule.analyze({
      filePath: 'empty.js',
      fileContent: '',
      ast: null,
      lines: []
    });
    expect(findings).toEqual([]);
  });
});
