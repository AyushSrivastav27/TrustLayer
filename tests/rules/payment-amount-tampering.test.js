import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/payment-amount-tampering.js';
import { parseSource } from '../../src/engine/ast-parser.js';

function analyzeCode(code, filePath = 'routes/checkout.js') {
  const { ast } = parseSource(code, filePath);
  const lines = code.split('\n');
  return rule.analyze({
    filePath,
    fileContent: code,
    ast,
    lines
  });
}

describe('Rule: payment/payment-amount-tampering', () => {
  it('flags direct req.body.amount in stripe.charges.create (true positive)', () => {
    const code = `
      router.post('/charge', async (req, res) => {
        const charge = await stripe.charges.create({
          amount: req.body.amount,
          currency: 'usd',
          source: req.body.stripeToken
        });
        res.json({ success: true, charge });
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('payment/payment-amount-tampering');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].codeSnippet).toContain('req.body.amount');
  });

  it('flags destructured amount from req.body flowing into stripe.paymentIntents.create', () => {
    const code = `
      app.post('/api/checkout', async (req, res) => {
        const { amount, currency } = req.body;
        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: currency || 'usd'
        });
        res.json({ clientSecret: paymentIntent.client_secret });
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('payment/payment-amount-tampering');
    expect(findings[0].severity).toBe('critical');
  });

  it('flags computed expressions derived from req.body (e.g. req.body.total * 100)', () => {
    const code = `
      router.post('/create-order', async (req, res) => {
        const order = await razorpay.orders.create({
          amount: req.body.total * 100,
          currency: 'INR'
        });
        res.json(order);
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('flags direct argument in razorpay.payments.capture', () => {
    const code = `
      router.post('/capture', async (req, res) => {
        const result = await razorpay.payments.capture(req.body.paymentId, req.body.amount);
        res.json(result);
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
  });

  it('flags nested amount in stripe.checkout.sessions.create', () => {
    const code = `
      router.post('/session', async (req, res) => {
        const session = await stripe.checkout.sessions.create({
          line_items: [{
            price_data: {
              unit_amount: req.body.amount,
              currency: 'usd'
            }
          }]
        });
        res.json({ id: session.id });
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(1);
  });

  it('ignores payment call with server-calculated database amount (true negative)', () => {
    const code = `
      router.post('/checkout', async (req, res) => {
        const product = await db.query('SELECT price FROM products WHERE id = ?', [req.body.productId]);
        const serverAmount = product.price * 100;
        const paymentIntent = await stripe.paymentIntents.create({
          amount: serverAmount,
          currency: 'usd'
        });
        res.json(paymentIntent);
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('ignores hardcoded literal amount (true negative)', () => {
    const code = `
      router.post('/fixed-fee', async (req, res) => {
        const charge = await stripe.charges.create({
          amount: 2500,
          currency: 'usd'
        });
        res.json(charge);
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('ignores non-payment calls even if req.body.amount is passed (edge case)', () => {
    const code = `
      router.post('/audit', (req, res) => {
        logger.info('Received amount', { amount: req.body.amount });
        res.sendStatus(200);
      });
    `;
    const findings = analyzeCode(code);
    expect(findings).toHaveLength(0);
  });

  it('handles null AST gracefully without throwing (edge case)', () => {
    const findings = rule.analyze({
      filePath: 'empty.js',
      fileContent: '',
      ast: null,
      lines: []
    });
    expect(findings).toEqual([]);
  });
});
