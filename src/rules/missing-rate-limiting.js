import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import {
  isExpressRoute,
  getExpressRouteDetails,
  unwrapNode,
  extractSnippet
} from '../utils/ast-helpers.js';

// Sensitive endpoints susceptible to brute-force or financial transaction abuse
const SENSITIVE_RATE_LIMIT_ROUTES = [
  /\/(login|signin|authenticate|auth\/login)/i,
  /\/(register|signup|create-account)/i,
  /\/(forgot-password|reset-password|change-password)/i,
  /\/(checkout|charge|pay|payment-intent)/i
];

const SENSITIVE_RATE_LIMIT_FILES = /(?:^|\/)(?:routes?\/)?(auth|checkout|payments?|billing|password)(\.|\/|$)/i;

// Common identifiers or method names indicating rate limiting
const RATE_LIMIT_REGEX = /rate-?limit|limiter|throttle|bruteforce|ddos|flood/i;
const RATE_LIMIT_NAMES = [
  'rateLimit',
  'rateLimiter',
  'limiter',
  'authLimiter',
  'loginLimiter',
  'apiLimiter',
  'checkoutLimiter',
  'paymentLimiter',
  'throttle',
  'throttler'
];

/**
 * Checks if a given AST node is a rate limiting middleware.
 *
 * @param {object} node
 * @returns {boolean}
 */
function isRateLimiterNode(node) {
  if (!node) return false;
  const unwrapped = unwrapNode(node);

  // Identifier: e.g. authLimiter, limiter, rateLimiter
  if (t.isIdentifier(unwrapped)) {
    return RATE_LIMIT_NAMES.includes(unwrapped.name) || RATE_LIMIT_REGEX.test(unwrapped.name);
  }

  // Call expression: rateLimit({ ... }), createLimiter(), limiter()
  if (t.isCallExpression(unwrapped)) {
    const callee = unwrapNode(unwrapped.callee);
    if (t.isIdentifier(callee)) {
      return RATE_LIMIT_NAMES.includes(callee.name) || RATE_LIMIT_REGEX.test(callee.name);
    }
    if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
      return RATE_LIMIT_NAMES.includes(callee.property.name) || RATE_LIMIT_REGEX.test(callee.property.name);
    }
  }

  return false;
}

/**
 * Determines whether an Express route is sensitive to brute force or automated spam.
 *
 * @param {string|null} routePath
 * @param {string} method
 * @param {string} filePath
 * @returns {boolean}
 */
function isRateLimitSensitive(routePath, method, filePath) {
  // Methods typically targeted by credential stuffing and payment carding
  const isTargetMethod = ['post', 'put', 'patch'].includes(method.toLowerCase());

  if (routePath) {
    for (const pattern of SENSITIVE_RATE_LIMIT_ROUTES) {
      if (pattern.test(routePath)) return true;
    }
  }

  if (isTargetMethod && SENSITIVE_RATE_LIMIT_FILES.test(filePath.replace(/\\/g, '/'))) {
    // Only flag endpoints doing mutations in auth/checkout routers
    return true;
  }

  return false;
}

/**
 * @typedef {import('../types/rule.js').Rule} Rule
 */

/** @type {Rule} */
export default {
  id: 'auth/missing-rate-limiting',
  name: 'Missing Rate Limiting',
  severity: 'medium',
  category: 'auth',
  description: 'Detects high-risk endpoints (authentication, password resets, checkout) lacking rate-limiting middleware.',
  defaultExplanation: 'Endpoints handling authentication, registration, password resets, or payment processing without rate limiting are susceptible to automated credential stuffing, dictionary attacks, and card testing scams.',
  defaultRemediation: 'Apply rate limiting middleware (such as express-rate-limit) globally or to the sensitive endpoint: router.post(\'/login\', authLimiter, loginHandler);',

  analyze(context) {
    const findings = [];
    const { filePath, ast, lines } = context;

    if (!ast) return findings;

    let hasGlobalLimiter = false;
    const protectedRouters = new Set();
    const protectedPrefixes = new Set();

    // First pass: identify router-level or app-level rate limiting middleware
    traverse(ast, {
      CallExpression(path) {
        if (!isExpressRoute(path.node)) return;

        const callee = unwrapNode(path.node.callee);
        const methodName = t.isMemberExpression(callee) && t.isIdentifier(callee.property)
          ? callee.property.name.toLowerCase()
          : '';

        if (methodName !== 'use') return;

        const args = path.node.arguments || [];
        if (args.length === 0) return;

        const receiverName = t.isMemberExpression(callee) && t.isIdentifier(callee.object)
          ? callee.object.name
          : null;

        // Check router.use(limiter) or app.use(limiter)
        for (const arg of args) {
          if (isRateLimiterNode(arg)) {
            if (receiverName && receiverName.toLowerCase().includes('app')) {
              hasGlobalLimiter = true;
            } else if (receiverName) {
              protectedRouters.add(receiverName);
            }
          }
        }

        // Check app.use('/api/auth', authLimiter)
        if (args.length >= 2 && t.isStringLiteral(args[0])) {
          const prefix = args[0].value;
          const mw = args[1];
          if (isRateLimiterNode(mw)) {
            protectedPrefixes.add(prefix);
          }
        }
      }
    });

    if (hasGlobalLimiter) {
      return findings;
    }

    // Second pass: inspect route declarations
    traverse(ast, {
      CallExpression(path) {
        if (!isExpressRoute(path.node)) return;

        const details = getExpressRouteDetails(path.node);
        if (!details) return;

        const { method, routePath, middlewares } = details;
        if (method === 'use') return;

        if (!isRateLimitSensitive(routePath, method, filePath)) {
          return;
        }

        const callee = unwrapNode(path.node.callee);
        const routerName = t.isMemberExpression(callee) && t.isIdentifier(callee.object)
          ? callee.object.name
          : null;

        // Check router-level rate limiting
        if (routerName && protectedRouters.has(routerName)) {
          return;
        }

        // Check prefix-level rate limiting
        if (routePath) {
          for (const prefix of protectedPrefixes) {
            if (routePath.startsWith(prefix)) {
              return;
            }
          }
        }

        // Check route-level rate limiting
        const hasRouteLimiter = middlewares.some(mw => isRateLimiterNode(mw));
        if (hasRouteLimiter) {
          return;
        }

        const loc = path.node.loc || { start: { line: 1, column: 0 } };
        const line = loc.start.line;
        const column = loc.start.column + 1;
        const displayRoute = routePath ? `"${routePath}"` : `in ${filePath}`;

        findings.push({
          ruleId: 'auth/missing-rate-limiting',
          severity: 'medium',
          file: filePath,
          line,
          column,
          codeSnippet: extractSnippet(lines, path.node),
          message: `Sensitive endpoint ${displayRoute} lacks rate limiting middleware`,
          explanation: 'Endpoints processing credentials, payment cards, or user registration without throttling allow automated attacks such as credential stuffing and brute force.',
          remediation: 'Attach a rate limiting middleware such as express-rate-limit to the route chain: router.post(\'/login\', authLimiter, handler);',
          confidence: 'high'
        });
      }
    });

    return findings;
  }
};
