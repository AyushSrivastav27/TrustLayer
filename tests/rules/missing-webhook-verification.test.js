import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/missing-webhook-verification.js';
import { parseSource } from '../../src/engine/ast-parser.js';

function analyzeCode(code, filePath = 'routes/webhook.js') {
  const { ast } = parseSource(code, filePath);
  const lines = code.split('\n');
  return rule.analyze({
    filePath,
    fileContent: code,
    ast,
    lines
  });
}

describe('Rule: payment/missing-webhook-verification', () => {
  it('flags unverified webhook route handler (true positive)', () => {
    const code = `
      router.post('/webhook', (req, res) => {
        const event = req.body;
        if (event.type === 'payment_intent.succeeded') {
          orders.fulfill(event.data.object.id);
        }
        res.json({ received: true });
      });
    `;
    const findings = analyzeCode(code, 'routes/payments.js');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('payment/missing-webhook-verification');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].codeSnippet).toContain("'/webhook'");
  });

  it('flags unverified POST route in webhook.js file even if routePath is "/" (true positive)', () => {
    const code = `
      router.post('/', (req, res) => {
        const event = req.body;
        orders.process(event);
        res.sendStatus(200);
      });
    `;
    const findings = analyzeCode(code, 'routes/webhook.js');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('payment/missing-webhook-verification');
  });

  it('flags unverified separate handler function reference', () => {
    const code = `
      function handleWebhook(req, res) {
        processEvent(req.body);
        res.send('ok');
      }
      router.post('/webhook', handleWebhook);
    `;
    const findings = analyzeCode(code, 'routes/events.js');
    expect(findings).toHaveLength(1);
  });

  it('ignores webhook handler using stripe.webhooks.constructEvent (true negative)', () => {
    const code = `
      router.post('/webhook', (req, res) => {
        const sig = req.headers['stripe-signature'];
        let event;
        try {
          event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        } catch (err) {
          return res.status(400).send(\`Webhook Error: \${err.message}\`);
        }
        if (event.type === 'payment_intent.succeeded') {
          fulfillOrder(event.data.object);
        }
        res.json({ received: true });
      });
    `;
    const findings = analyzeCode(code, 'routes/webhook.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores webhook handler using crypto.timingSafeEqual (true negative)', () => {
    const code = `
      router.post('/callback', (req, res) => {
        const signature = req.headers['x-signature'];
        const expected = crypto.createHmac('sha256', secret).update(req.body).digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
          return res.status(401).send('Invalid signature');
        }
        fulfill(req.body);
        res.sendStatus(200);
      });
    `;
    const findings = analyzeCode(code, 'routes/callback.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores webhook route protected with verification middleware (true negative)', () => {
    const code = `
      router.post('/webhook', verifyWebhookSignature, (req, res) => {
        fulfill(req.body);
        res.sendStatus(200);
      });
    `;
    const findings = analyzeCode(code, 'routes/webhook.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores regular non-webhook routes (edge case)', () => {
    const code = `
      router.post('/products', (req, res) => {
        addProduct(req.body);
        res.sendStatus(201);
      });
    `;
    const findings = analyzeCode(code, 'routes/products.js');
    expect(findings).toHaveLength(0);
  });

  it('ignores GET status routes on /webhook (edge case)', () => {
    const code = `
      router.get('/webhook', (req, res) => {
        res.send('Webhook listener active');
      });
    `;
    const findings = analyzeCode(code, 'routes/webhook.js');
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
