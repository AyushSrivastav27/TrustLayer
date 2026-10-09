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

  it('recognizes app.use("/api", authenticate) and protects subroutes (Issue M4-3 true negative)', () => {
    const code = `
      app.use('/api', authenticate);
      app.get('/api/orders', (req, res) => {
        res.json({ orders: [] });
      });
      app.post('/api/checkout', (req, res) => {
        res.json({ status: 'ok' });
      });
    `;
    const findings = analyzeCode(code, 'app.js');
    expect(findings).toHaveLength(0);
  });

  it('flags routes outside app.use("/api", authenticate) prefix (true positive)', () => {
    const code = `
      app.use('/api', authenticate);
      app.get('/orders', (req, res) => {
        res.json({ orders: [] });
      });
    `;
    const findings = analyzeCode(code, 'app.js');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('auth/missing-auth-middleware');
  });

  it('recognizes global app.use(authenticate) without path prefix (true negative)', () => {
    const code = `
      app.use(requireAuth);
      app.get('/api/orders', (req, res) => {
        res.json({ orders: [] });
      });
    `;
    const findings = analyzeCode(code, 'app.js');
    expect(findings).toHaveLength(0);
  });

  it('recognizes router mounted under protected prefix with auth middleware (true negative)', () => {
    const code = `
      app.use('/api', authenticate, ordersRouter);
      ordersRouter.get('/orders', (req, res) => {
        res.json({ orders: [] });
      });
    `;
    const findings = analyzeCode(code, 'app.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores webhook endpoints to prevent collision with missing-webhook-verification (true negative)', () => {
    const code = `
      router.post('/api/payments/webhook', (req, res) => {
        const event = req.body;
        res.json({ received: true });
      });
      app.post('/webhook', (req, res) => {
        res.sendStatus(200);
      });
      app.post('/stripe-webhook', (req, res) => {
        res.sendStatus(200);
      });
    `;
    const findings = analyzeCode(code, 'routes/payments.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores routes in dedicated webhook router file (routes/webhook.js) (true negative)', () => {
    const code = `
      router.post('/', (req, res) => {
        res.sendStatus(200);
      });
    `;
    const findings = analyzeCode(code, 'routes/webhook.js');
    expect(findings).toHaveLength(0);
  });

  it('flags sensitive non-webhook route while ignoring webhook endpoint in same router', () => {
    const code = `
      router.post('/checkout', (req, res) => {
        res.json({ order: 123 });
      });
      router.post('/webhook', (req, res) => {
        res.sendStatus(200);
      });
    `;
    const findings = analyzeCode(code, 'routes/payments.js');
    expect(findings).toHaveLength(1);
    expect(findings[0].codeSnippet).toContain('/checkout');
  });
});

