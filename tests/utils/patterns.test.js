import { describe, it, expect } from 'vitest';
import {
  HTTP_SOURCES,
  AMOUNT_KEYS,
  STATUS_KEYS,
  AUTH_MIDDLEWARE_NAMES,
  SENSITIVE_ROUTE_PATTERNS,
  PUBLIC_ROUTE_PATTERNS,
  PAYMENT_SINKS,
  WEBHOOK_VERIFIERS,
  DB_SINKS,
  DB_OBJECTS,
  SQL_KEYWORDS_REGEX,
  WEAK_HASH_ALGORITHMS,
  SECRET_PATTERNS
} from '../../src/utils/patterns.js';

describe('Utils: patterns', () => {
  describe('Constants & Signatures Verification', () => {
    it('exports expected HTTP sources and sensitive payment keys', () => {
      expect(HTTP_SOURCES).toContain('body');
      expect(HTTP_SOURCES).toContain('query');
      expect(HTTP_SOURCES).toContain('params');

      expect(AMOUNT_KEYS).toContain('amount');
      expect(AMOUNT_KEYS).toContain('price');
      expect(AMOUNT_KEYS).toContain('total');

      expect(STATUS_KEYS).toContain('paymentStatus');
      expect(STATUS_KEYS).toContain('paid');
    });

    it('exports expected auth middleware identifiers and verifiers', () => {
      expect(AUTH_MIDDLEWARE_NAMES).toContain('authenticate');
      expect(AUTH_MIDDLEWARE_NAMES).toContain('requireAuth');
      expect(AUTH_MIDDLEWARE_NAMES).toContain('verifyToken');

      expect(WEBHOOK_VERIFIERS).toContain('constructEvent');
      expect(WEBHOOK_VERIFIERS).toContain('timingSafeEqual');
      expect(WEBHOOK_VERIFIERS).toContain('verifyPaymentSignature');
    });

    it('exports database sinks and ORM client identifiers', () => {
      expect(DB_SINKS).toContain('query');
      expect(DB_SINKS).toContain('execute');
      expect(DB_SINKS).toContain('all');

      expect(DB_OBJECTS).toContain('db');
      expect(DB_OBJECTS).toContain('pool');
      expect(DB_OBJECTS).toContain('knex');
      expect(DB_OBJECTS).toContain('prisma');
    });

    it('exports weak hash algorithms and secret patterns', () => {
      expect(WEAK_HASH_ALGORITHMS).toContain('md5');
      expect(WEAK_HASH_ALGORITHMS).toContain('sha1');
      expect(WEAK_HASH_ALGORITHMS).toContain('des');
      expect(WEAK_HASH_ALGORITHMS).toContain('rc4');

      expect(SECRET_PATTERNS.some(p => p.name.includes('Stripe Secret Key'))).toBe(true);
      expect(SECRET_PATTERNS.some(p => p.name.includes('AWS Access Key'))).toBe(true);
      expect(SECRET_PATTERNS.some(p => p.name.includes('Generic API Key'))).toBe(true);
    });
  });

  describe('Regex Matching & Precision', () => {
    it('detects SQL keywords in dynamic queries', () => {
      expect(SQL_KEYWORDS_REGEX.test('SELECT * FROM users')).toBe(true);
      expect(SQL_KEYWORDS_REGEX.test('INSERT INTO orders')).toBe(true);
      expect(SQL_KEYWORDS_REGEX.test('WHERE id = 1')).toBe(true);
      expect(SQL_KEYWORDS_REGEX.test('hello world non-sql statement')).toBe(false);
    });

    it('matches sensitive and public route patterns accurately', () => {
      const isSensitive = (path) => SENSITIVE_ROUTE_PATTERNS.some(r => r.test(path));
      const isPublic = (path) => PUBLIC_ROUTE_PATTERNS.some(r => r.test(path));

      expect(isSensitive('/api/checkout')).toBe(true);
      expect(isSensitive('/orders/123')).toBe(true);
      expect(isSensitive('/api/payments/charge')).toBe(true);

      expect(isPublic('/api/login')).toBe(true);
      expect(isPublic('/public/health')).toBe(true);
      expect(isPublic('/api/products/search')).toBe(true);
    });

    it('validates secret patterns for Stripe, AWS, and generic keys', () => {
      const genericPattern = SECRET_PATTERNS.find(p => p.name === 'Generic API Key / Secret');
      expect(genericPattern).toBeDefined();

      // Matches with double quotes
      expect(genericPattern.regex.test('api_key = "1234567890abcdef12345"')).toBe(true);
      // Matches with single quotes
      expect(genericPattern.regex.test("jwt_secret: '1234567890abcdef12345'")).toBe(true);
      // Rejects mismatched quotes
      expect(genericPattern.regex.test('api_key = "1234567890abcdef12345\'')).toBe(false);
    });
  });

  describe('Scanner Self-Defense: ReDoS & Backtracking Resistance', () => {
    it('evaluates generic API key regex on huge adversarial input without catastrophic backtracking', () => {
      const genericPattern = SECRET_PATTERNS.find(p => p.name === 'Generic API Key / Secret');
      
      // Adversarial payload: prefix followed by 50,000 repeating characters without closing quote
      const adversarialString = 'api_key = "' + 'A'.repeat(50_000);
      
      const startTime = Date.now();
      const result = genericPattern.regex.test(adversarialString);
      const durationMs = Date.now() - startTime;

      expect(result).toBe(false);
      // Execution must complete in under 50ms without freezing
      expect(durationMs).toBeLessThan(50);
    });

    it('evaluates SQL keywords regex against adversarial whitespace without stalling', () => {
      const adversarialSql = 'SELECT ' + ' '.repeat(50_000) + 'non_keyword';

      const startTime = Date.now();
      const result = SQL_KEYWORDS_REGEX.test(adversarialSql);
      const durationMs = Date.now() - startTime;

      expect(result).toBe(true); // 'SELECT' matched at start
      expect(durationMs).toBeLessThan(50);
    });

    it('evaluates route patterns against long path strings without stalling', () => {
      const longPath = '/api/' + 'a'.repeat(50_000);

      const startTime = Date.now();
      for (const pattern of SENSITIVE_ROUTE_PATTERNS) {
        pattern.test(longPath);
      }
      for (const pattern of PUBLIC_ROUTE_PATTERNS) {
        pattern.test(longPath);
      }
      const durationMs = Date.now() - startTime;

      expect(durationMs).toBeLessThan(50);
    });
  });
});
