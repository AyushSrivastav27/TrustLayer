/**
 * Shared regex patterns and security identifiers used across TrustLayer rules.
 */

// Express request user-input sources
export const HTTP_SOURCES = ['body', 'query', 'params', 'headers', 'cookies'];

// Sensitive payment amount/price keys
// Note: 'price' is evaluated in numeric contexts by payment rules to distinguish monetary amounts from catalog/Price IDs
export const AMOUNT_KEYS = [
  'amount',
  'price',
  'total',
  'cost',
  'subtotal',
  'payment_amount',
  'order_total'
];

// Client-side status keys (payment status spoofing)
export const STATUS_KEYS = [
  'paymentStatus',
  'payment_status',
  'status',
  'paid',
  'isPaid'
];

// Known Express authentication middleware identifiers
export const AUTH_MIDDLEWARE_NAMES = [
  'isAuthenticated',
  'authenticate',
  'requireAuth',
  'verifyToken',
  'jwtCheck',
  'ensureAuthenticated',
  'checkAuth',
  'protect',
  'auth'
];

// Sensitive route path keywords that require authentication
export const SENSITIVE_ROUTE_PATTERNS = [
  /\/api\/(checkout|orders?|payments?|charge|cart|user|account|admin|billing)/i,
  /\/(checkout|orders?|payments?|charge|cart|user|account|admin|billing)/i
];

// Public route path keywords that do not need authentication
export const PUBLIC_ROUTE_PATTERNS = [
  /\/api\/(login|register|signup|auth|public|health|products?|items?|catalog|webhooks?)/i,
  /\/(login|register|signup|auth|public|health|products?|items?|catalog|webhooks?)/i
];

// Known payment SDK sink method names (object.method or chain)
export const PAYMENT_SINKS = [
  { object: 'stripe', property: 'charges', method: 'create' },
  { object: 'stripe', property: 'paymentIntents', method: 'create' },
  { object: 'stripe', property: 'checkout', method: 'sessions.create' },
  { object: 'razorpay', property: 'orders', method: 'create' },
  { object: 'razorpay', property: 'payments', method: 'capture' }
];

// Webhook signature verification functions/methods
export const WEBHOOK_VERIFIERS = [
  'constructEvent',          // stripe.webhooks.constructEvent
  'verifyPaymentSignature',  // razorpay.utils.verifyPaymentSignature
  'timingSafeEqual'          // crypto.timingSafeEqual
];

// Database query sinks for SQL injection detection
export const DB_SINKS = ['query', 'execute', 'exec', 'run', 'all', 'get', 'raw', '$queryRawUnsafe', '$executeRawUnsafe'];
export const DB_OBJECTS = ['db', 'pool', 'connection', 'client', 'knex', 'sequelize', 'prisma'];

// Non-Express receiver objects to prevent false-positive route detections
export const NON_EXPRESS_OBJECTS = new Set([
  'db', 'pool', 'connection', 'client', 'knex', 'sequelize', 'prisma',
  'sqlite', 'stmt', 'statement', 'redis', 'cache',
  'axios', 'http', 'https', 'fetch', 'fs', 'path', 'url', 'console',
  'logger', 'log', 'Math', 'JSON', 'Object', 'Array', 'Promise'
]);

// SQL keyword patterns for string concatenation detection
export const SQL_KEYWORDS_REGEX = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|UNION\s+ALL|UNION\s+SELECT|WHERE)\b/i;

// Weak cryptographic algorithms
export const WEAK_HASH_ALGORITHMS = ['md5', 'sha1', 'des', 'rc4'];

// Hardcoded secrets patterns
export const SECRET_PATTERNS = [
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'Stripe Test Key', regex: /sk_test_[0-9a-zA-Z]{24,}/ },
  { name: 'Stripe Webhook Secret', regex: /whsec_[0-9a-zA-Z]{24,}/ },
  { name: 'Razorpay Key Secret', regex: /rzp_(?:test|live)_[0-9a-zA-Z]{14,}/ },
  { name: 'AWS Access Key ID', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/ },
  { name: 'Generic API Key / Secret', regex: /(?:api[_-]?key|jwt[_-]?secret|jwt[_-]?token|app[_-]?secret|private[_-]?key)\s*[:=]\s*['"`][A-Za-z0-9+/=_-]{16,}['"`]/i }
];
