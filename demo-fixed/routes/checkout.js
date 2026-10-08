import express from 'express';
import Stripe from 'stripe';
import { requireAuth } from '../middleware/auth.js';
import { db } from '../../demo/db/setup.js';

const router = express.Router();
router.use(requireAuth);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'dummy_stripe_key_not_configured');

const checkoutSchema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid checkout data');
    return data;
  }
};

/**
 * POST /api/checkout/charge
 * SECURE: Server-side price calculation prevents payment amount tampering.
 */
router.post('/charge', async (req, res) => {
  const data = checkoutSchema.parse(req.body);
  const { productId, currency, source } = data;

  try {
    // SECURE: Authoritative product price looked up directly in database
    const product = db.prepare('SELECT price FROM products WHERE id = ?').get([productId]);

    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // SECURE: Server calculates charge amount; client has no control over price
    const verifiedAmount = Math.round(product.price * 100);

    const charge = await stripe.charges.create({
      amount: verifiedAmount,
      currency: currency || 'usd',
      source: source || 'tok_visa',
      description: `Charge for product #${productId}`
    });

    res.json({
      success: true,
      chargeId: charge.id,
      amountPaid: charge.amount
    });
  } catch (err) {
    res.status(500).json({ error: 'Payment failed', message: err.message });
  }
});

/**
 * POST /api/checkout/payment-intent
 * SECURE: Server-calculated price lookup for PaymentIntent
 */
router.post('/payment-intent', async (req, res) => {
  const data = checkoutSchema.parse(req.body);
  const { productId, currency } = data;

  try {
    const product = db.prepare('SELECT price FROM products WHERE id = ?').get([productId]);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const verifiedAmount = Math.round(product.price * 100);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: verifiedAmount,
      currency: currency || 'usd'
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      id: paymentIntent.id
    });
  } catch (err) {
    res.status(500).json({ error: 'Intent creation failed', message: err.message });
  }
});

export default router;
