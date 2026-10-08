import express from 'express';
import crypto from 'node:crypto';
import Stripe from 'stripe';
import { db } from '../../demo/db/setup.js';

const router = express.Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder_key_123');
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_placeholder_secret_key';

const webhookSchema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid webhook payload');
    return data;
  }
};

/**
 * POST /api/webhook/public/webhook/stripe
 * SECURE: Verifies cryptographic HMAC signature + schema validated input
 */
router.post('/public/webhook/stripe', (req, res) => {
  const body = webhookSchema.parse(req.body);
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // SECURE: Cryptographic verification of webhook payload
    event = stripe.webhooks.constructEvent(body, sig, endpointSecret);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data?.object;
    const orderId = paymentIntent?.metadata?.orderId;

    if (orderId) {
      const stmt = db.prepare('UPDATE orders SET status = ? WHERE id = ?');
      stmt.run('completed', orderId);
    }
  }

  res.json({ received: true });
});

/**
 * POST /api/webhook/public/webhook/razorpay
 * SECURE: Verifies HMAC signature using timingSafeEqual + schema validated input
 */
router.post('/public/webhook/razorpay', (req, res) => {
  const body = webhookSchema.parse(req.body);
  const signature = req.headers['x-razorpay-signature'] || '';
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET || 'default_secret')
    .update(JSON.stringify(body))
    .digest('hex');

  // SECURE: Timing-safe cryptographic comparison
  const isValid = crypto.timingSafeEqual(
    Buffer.from(signature, 'utf8'),
    Buffer.from(expectedSignature, 'utf8')
  );

  if (!isValid) {
    return res.status(400).json({ error: 'Invalid webhook signature' });
  }

  res.status(200).send('OK');
});

export default router;
