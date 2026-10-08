import { describe, it, expect } from 'vitest';
import * as babelParser from '@babel/parser';
import * as astHelpers from '../../src/utils/ast-helpers.js';
import * as patterns from '../../src/utils/patterns.js';

function parseExpr(code) {
  const ast = babelParser.parse(code, { sourceType: 'module' });
  // ast.program.body[0] is ExpressionStatement
  return ast.program.body[0].expression;
}

function parseSnippet(code) {
  const ast = babelParser.parse(code, { sourceType: 'module' });
  return ast.program.body[0];
}

describe('AST Helpers - isMethodCall', () => {
  it('identifies single-level method calls (e.g. db.query)', () => {
    const node = parseExpr('db.query("SELECT 1")');
    expect(astHelpers.isMethodCall(node, 'db', 'query')).toBe(true);
    expect(astHelpers.isMethodCall(node, 'db', 'exec')).toBe(false);
    expect(astHelpers.isMethodCall(node, 'pool', 'query')).toBe(false);
  });

  it('identifies two-level chained method calls (e.g. stripe.charges.create)', () => {
    const node = parseExpr('stripe.charges.create({ amount: 100 })');
    expect(astHelpers.isMethodCall(node, 'stripe', 'create')).toBe(true);
  });

  it('returns false for non-call expressions or mismatched structures', () => {
    const idNode = parseExpr('myVariable');
    expect(astHelpers.isMethodCall(idNode, 'db', 'query')).toBe(false);

    const callFnNode = parseExpr('query("SELECT 1")');
    expect(astHelpers.isMethodCall(callFnNode, 'db', 'query')).toBe(false);

    expect(astHelpers.isMethodCall(null, 'db', 'query')).toBe(false);
    expect(astHelpers.isMethodCall(undefined, 'db', 'query')).toBe(false);
  });
});

describe('AST Helpers - isExpressRoute', () => {
  it('returns true for common Express routing methods', () => {
    const getCall = parseExpr('app.get("/users", handler)');
    const postCall = parseExpr('router.post("/checkout", auth, handler)');
    const putCall = parseExpr('route.put("/update", handler)');
    const deleteCall = parseExpr('app.delete("/remove", handler)');
    const useCall = parseExpr('app.use(middleware)');

    expect(astHelpers.isExpressRoute(getCall)).toBe(true);
    expect(astHelpers.isExpressRoute(postCall)).toBe(true);
    expect(astHelpers.isExpressRoute(putCall)).toBe(true);
    expect(astHelpers.isExpressRoute(deleteCall)).toBe(true);
    expect(astHelpers.isExpressRoute(useCall)).toBe(true);
  });

  it('returns false for non-route methods and non-call nodes', () => {
    const customCall = parseExpr('console.log("hello")');
    const directCall = parseExpr('myFunc()');
    const identifierNode = parseExpr('foo');

    expect(astHelpers.isExpressRoute(customCall)).toBe(false);
    expect(astHelpers.isExpressRoute(directCall)).toBe(false);
    expect(astHelpers.isExpressRoute(identifierNode)).toBe(false);
    expect(astHelpers.isExpressRoute(null)).toBe(false);
  });
});

describe('AST Helpers - getExpressRouteDetails', () => {
  it('extracts method, route path, middlewares, and handler', () => {
    const node = parseExpr('router.post("/api/checkout", requireAuth, rateLimiter, checkoutHandler)');
    const details = astHelpers.getExpressRouteDetails(node);

    expect(details).not.toBeNull();
    expect(details.method).toBe('post');
    expect(details.routePath).toBe('/api/checkout');
    expect(details.middlewares.length).toBe(2);
    expect(details.middlewares[0].name).toBe('requireAuth');
    expect(details.middlewares[1].name).toBe('rateLimiter');
    expect(details.handler).not.toBeNull();
    expect(details.handler.name).toBe('checkoutHandler');
  });

  it('handles routes without path string (e.g. app.use(auth))', () => {
    const node = parseExpr('app.use(authMiddleware)');
    const details = astHelpers.getExpressRouteDetails(node);

    expect(details).not.toBeNull();
    expect(details.method).toBe('use');
    expect(details.routePath).toBeNull();
    expect(details.middlewares).toEqual([]);
    expect(details.handler.name).toBe('authMiddleware');
  });

  it('returns null for non-express routes or empty arguments', () => {
    const nonRoute = parseExpr('doSomething()');
    expect(astHelpers.getExpressRouteDetails(nonRoute)).toBeNull();

    const emptyRoute = parseExpr('app.get()');
    expect(astHelpers.getExpressRouteDetails(emptyRoute)).toBeNull();
  });
});

describe('AST Helpers - isReqAccess', () => {
  it('detects direct access on req sources', () => {
    expect(astHelpers.isReqAccess(parseExpr('req.body'))).toBe(true);
    expect(astHelpers.isReqAccess(parseExpr('req.query'))).toBe(true);
    expect(astHelpers.isReqAccess(parseExpr('req.params'))).toBe(true);
    expect(astHelpers.isReqAccess(parseExpr('req.headers'))).toBe(true);
    expect(astHelpers.isReqAccess(parseExpr('req.cookies'))).toBe(true);
  });

  it('detects nested property access from req', () => {
    expect(astHelpers.isReqAccess(parseExpr('req.body.amount'))).toBe(true);
    expect(astHelpers.isReqAccess(parseExpr('req.params.id'))).toBe(true);
    expect(astHelpers.isReqAccess(parseExpr('req.query.filter.tag'))).toBe(true);
  });

  it('rejects non-req objects or unrelated properties', () => {
    expect(astHelpers.isReqAccess(parseExpr('other.body'))).toBe(false);
    expect(astHelpers.isReqAccess(parseExpr('req.randomProp'))).toBe(false);
    expect(astHelpers.isReqAccess(parseExpr('req'))).toBe(false);
    expect(astHelpers.isReqAccess(null)).toBe(false);
  });

  it('supports custom sources list', () => {
    expect(astHelpers.isReqAccess(parseExpr('req.session'), ['session'])).toBe(true);
    expect(astHelpers.isReqAccess(parseExpr('req.body'), ['session'])).toBe(false);
  });
});

describe('AST Helpers - isReqPropertyAccess', () => {
  it('matches specified properties on req access', () => {
    const amountNode = parseExpr('req.body.amount');
    const priceNode = parseExpr('req.query.price');
    const otherNode = parseExpr('req.body.email');

    expect(astHelpers.isReqPropertyAccess(amountNode, patterns.AMOUNT_KEYS)).toBe(true);
    expect(astHelpers.isReqPropertyAccess(priceNode, patterns.AMOUNT_KEYS)).toBe(true);
    expect(astHelpers.isReqPropertyAccess(otherNode, patterns.AMOUNT_KEYS)).toBe(false);
  });

  it('returns false when property is not on req or not member expression', () => {
    expect(astHelpers.isReqPropertyAccess(parseExpr('payment.amount'), ['amount'])).toBe(false);
    expect(astHelpers.isReqPropertyAccess(parseExpr('req.body'), ['body'])).toBe(false);
    expect(astHelpers.isReqPropertyAccess(null, ['amount'])).toBe(false);
  });
});

describe('AST Helpers - calculateEntropy', () => {
  it('calculates 0 for empty or repeating strings', () => {
    expect(astHelpers.calculateEntropy('')).toBe(0);
    expect(astHelpers.calculateEntropy(null)).toBe(0);
    expect(astHelpers.calculateEntropy(undefined)).toBe(0);
    expect(astHelpers.calculateEntropy('aaaaaaa')).toBe(0);
  });

  it('calculates positive entropy for high-diversity secret strings', () => {
    const entropy = astHelpers.calculateEntropy('xK9#mQ2$vL8*pZ5!nB3@rW7&tY1%eU4^dummy_secret_entropy');
    expect(entropy).toBeGreaterThan(3.5);
  });
});

describe('AST Helpers - extractSnippet', () => {
  const lines = [
    'const stripe = require("stripe");',
    'app.post("/pay", (req, res) => {',
    '  const amount = req.body.amount;',
    '});'
  ];

  it('extracts trimmed line corresponding to node loc', () => {
    const node = parseSnippet('const amount = req.body.amount;');
    node.loc = { start: { line: 3, column: 2 } };

    const snippet = astHelpers.extractSnippet(lines, node);
    expect(snippet).toBe('const amount = req.body.amount;');
  });

  it('handles missing lines or loc safely', () => {
    expect(astHelpers.extractSnippet([], null)).toBe('');
    expect(astHelpers.extractSnippet(lines, {})).toBe('');
    expect(astHelpers.extractSnippet(null, { loc: { start: { line: 1 } } })).toBe('');
  });
});

describe('Security Patterns - Validation', () => {
  it('validates SQL injection regex matches common keywords', () => {
    expect(patterns.SQL_KEYWORDS_REGEX.test('SELECT * FROM users')).toBe(true);
    expect(patterns.SQL_KEYWORDS_REGEX.test('INSERT INTO orders VALUES (1)')).toBe(true);
    expect(patterns.SQL_KEYWORDS_REGEX.test('UPDATE accounts SET bal = 0')).toBe(true);
    expect(patterns.SQL_KEYWORDS_REGEX.test('DELETE FROM items')).toBe(true);
    expect(patterns.SQL_KEYWORDS_REGEX.test('const x = 42')).toBe(false);
  });

  it('validates secret patterns correctly detect key formats', () => {
    const stripeLive = patterns.SECRET_PATTERNS.find(p => p.name === 'Stripe Secret Key');
    const mockLiveKey = ['sk', 'live', '51Mszabcdefghijklmnopqrstuv123456'].join('_');
    expect(stripeLive.regex.test(mockLiveKey)).toBe(true);
    expect(stripeLive.regex.test('regular_variable_name')).toBe(false);

    const stripeTest = patterns.SECRET_PATTERNS.find(p => p.name === 'Stripe Test Key');
    const mockTestKey = ['sk', 'test', '51Mszabcdefghijklmnopqrstuv123456'].join('_');
    expect(stripeTest.regex.test(mockTestKey)).toBe(true);

    const razorpayKey = patterns.SECRET_PATTERNS.find(p => p.name === 'Razorpay Key Secret');
    const mockRzpTest = ['rzp', 'test', '1DP5mmOlF5G5ag'].join('_');
    const mockRzpLive = ['rzp', 'live', '1DP5mmOlF5G5ag'].join('_');
    expect(razorpayKey.regex.test(mockRzpTest)).toBe(true);
    expect(razorpayKey.regex.test(mockRzpLive)).toBe(true);
  });

  it('verifies route pattern classification', () => {
    expect(patterns.SENSITIVE_ROUTE_PATTERNS.some(r => r.test('/api/checkout'))).toBe(true);
    expect(patterns.SENSITIVE_ROUTE_PATTERNS.some(r => r.test('/api/orders'))).toBe(true);
    expect(patterns.PUBLIC_ROUTE_PATTERNS.some(r => r.test('/api/products'))).toBe(true);
    expect(patterns.PUBLIC_ROUTE_PATTERNS.some(r => r.test('/api/login'))).toBe(true);
  });

  it('validates NON_EXPRESS_OBJECTS contains common database, client, and utility objects', () => {
    expect(patterns.NON_EXPRESS_OBJECTS instanceof Set).toBe(true);
    expect(patterns.NON_EXPRESS_OBJECTS.has('db')).toBe(true);
    expect(patterns.NON_EXPRESS_OBJECTS.has('pool')).toBe(true);
    expect(patterns.NON_EXPRESS_OBJECTS.has('axios')).toBe(true);
    expect(patterns.NON_EXPRESS_OBJECTS.has('console')).toBe(true);
    expect(patterns.NON_EXPRESS_OBJECTS.has('router')).toBe(false);
    expect(patterns.NON_EXPRESS_OBJECTS.has('app')).toBe(false);
  });
});

