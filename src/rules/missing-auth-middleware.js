import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import { isExpressRoute, getExpressRouteDetails, extractSnippet } from '../utils/ast-helpers.js';
import {
  AUTH_MIDDLEWARE_NAMES,
  SENSITIVE_ROUTE_PATTERNS,
  PUBLIC_ROUTE_PATTERNS
} from '../utils/patterns.js';

const SENSITIVE_FILE_REGEX = /(?:^|\/)(?:routes?\/)?(orders?|checkout|payments?|cart|admin|billing|users?)(\.|\/|$)/i;
const AUTH_REGEX = /auth|protect|jwt|token|session|guard|permission|requireAuth|checkAuth|verifyToken/i;

/**
 * Checks if an AST node represents an authentication middleware.
 *
 * @param {object} node - Babel AST node
 * @returns {boolean}
 */
function isAuthMiddlewareNode(node) {
  if (!node) return false;

  // Direct identifier: authenticate, requireAuth, isAuthenticated, etc.
  if (t.isIdentifier(node)) {
    return AUTH_MIDDLEWARE_NAMES.includes(node.name) || AUTH_REGEX.test(node.name);
  }

  // Call expression: passport.authenticate('jwt'), auth(), requireAuth({ role: 'admin' })
  if (t.isCallExpression(node)) {
    const { callee } = node;
    if (t.isIdentifier(callee)) {
      return AUTH_MIDDLEWARE_NAMES.includes(callee.name) || AUTH_REGEX.test(callee.name);
    }
    if (t.isMemberExpression(callee)) {
      const prop = callee.property;
      if (t.isIdentifier(prop) && (AUTH_MIDDLEWARE_NAMES.includes(prop.name) || AUTH_REGEX.test(prop.name))) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Determines whether a given route path or file represents a sensitive endpoint needing authentication.
 *
 * @param {string|null} routePath - Express route path string
 * @param {string} filePath - Path of the file containing the route
 * @returns {boolean}
 */
function isSensitiveRoute(routePath, filePath) {
  const normalizedFilePath = filePath.replace(/\\/g, '/');

  // Explicit public paths are always whitelisted
  if (routePath) {
    for (const pattern of PUBLIC_ROUTE_PATTERNS) {
      if (pattern.test(routePath)) return false;
    }

    // Explicit sensitive path match: e.g. /api/orders, /checkout, /user/profile
    for (const pattern of SENSITIVE_ROUTE_PATTERNS) {
      if (pattern.test(routePath)) return true;
    }
  }

  // Root or relative endpoints inside sensitive router modules (e.g. routes/orders.js, routes/checkout.js)
  if (SENSITIVE_FILE_REGEX.test(normalizedFilePath)) {
    // If it's a known public subroute, allow it
    if (routePath && PUBLIC_ROUTE_PATTERNS.some(p => p.test(routePath))) {
      return false;
    }
    return true;
  }

  return false;
}

const NON_EXPRESS_OBJECTS = new Set([
  'db', 'pool', 'connection', 'client', 'knex', 'sequelize', 'prisma',
  'sqlite', 'stmt', 'statement', 'redis', 'cache',
  'axios', 'http', 'https', 'fetch', 'fs', 'path', 'url', 'console',
  'logger', 'log', 'Math', 'JSON', 'Object', 'Array', 'Promise'
]);

/**
 * Validates that a CallExpression is genuinely an Express route declaration.
 *
 * @param {object} node - Babel CallExpression node
 * @param {object} details - Extracted route details
 * @returns {boolean}
 */
function isValidExpressRoute(node, details) {
  if (!details) return false;
  const { callee } = node;

  if (t.isMemberExpression(callee) && t.isIdentifier(callee.object)) {
    if (NON_EXPRESS_OBJECTS.has(callee.object.name)) {
      return false;
    }
  }

  // Non-middleware routes (get, post, put, delete, patch) must have at least path and handler (length >= 2)
  if (details.method !== 'use') {
    if (node.arguments.length < 2) return false;
    const lastArg = node.arguments[node.arguments.length - 1];
    if (!t.isFunction(lastArg) && !t.isArrowFunctionExpression(lastArg) && !t.isFunctionExpression(lastArg) && !t.isIdentifier(lastArg)) {
      return false;
    }
  }

  return true;
}

export default {
  id: 'auth/missing-auth-middleware',
  name: 'Missing Authentication Middleware',
  severity: 'high',
  category: 'auth',
  description: 'Detects sensitive Express route handlers lacking authentication guards.',
  defaultExplanation: 'Endpoints managing sensitive operations such as orders, checkout, user accounts, and billing must enforce authentication. Omitting authentication middleware allows unauthenticated callers to access or modify sensitive customer data and transactions.',
  defaultRemediation: 'Apply authentication middleware (e.g. requireAuth, authenticate, or verifyToken) to the route chain or apply router.use(authenticate) at the router level.',

  /**
   * Analyzes an AST for missing authentication middleware on sensitive routes.
   *
   * @param {import('../types/rule.js').AnalysisContext} context
   * @returns {import('../types/finding.js').Finding[]}
   */
  analyze(context) {
    const findings = [];
    const { filePath, ast, lines } = context;
    if (!ast) return findings;

    // Track routers that have file-level or router-level auth middleware applied via router.use(...)
    const protectedRouters = new Set();

    // First pass: identify router-level auth middleware
    traverse(ast, {
      CallExpression(path) {
        if (!isExpressRoute(path.node)) return;
        const details = getExpressRouteDetails(path.node);
        if (!isValidExpressRoute(path.node, details)) return;

        if (details.method === 'use') {
          const callee = path.node.callee;
          const routerName = t.isMemberExpression(callee) && t.isIdentifier(callee.object) ? callee.object.name : null;

          // Check all arguments to .use(...) for auth middleware
          const hasAuth = path.node.arguments.some(arg => isAuthMiddlewareNode(arg));
          if (hasAuth && routerName) {
            protectedRouters.add(routerName);
          }
        }
      }
    });

    // Second pass: inspect sensitive route definitions
    traverse(ast, {
      CallExpression(path) {
        if (!isExpressRoute(path.node)) return;

        const details = getExpressRouteDetails(path.node);
        if (!isValidExpressRoute(path.node, details)) return;

        const { method, routePath, middlewares } = details;

        // Skip middleware declarations (.use())
        if (method === 'use') return;

        // Check if the route is sensitive
        if (!isSensitiveRoute(routePath, filePath)) return;

        // Check if the router has router-level auth middleware
        const callee = path.node.callee;
        const routerName = t.isMemberExpression(callee) && t.isIdentifier(callee.object) ? callee.object.name : null;
        if (routerName && protectedRouters.has(routerName)) {
          return;
        }

        // Check if any route-level middleware enforces authentication
        const hasRouteAuth = middlewares.some(mw => isAuthMiddlewareNode(mw));
        if (hasRouteAuth) {
          return;
        }

        // Vulnerability found: sensitive route without auth middleware
        const line = path.node.loc ? path.node.loc.start.line : 1;
        const column = path.node.loc ? path.node.loc.start.column + 1 : 1;
        const displayPath = routePath ? `"${routePath}"` : `in ${filePath}`;

        findings.push({
          ruleId: 'auth/missing-auth-middleware',
          severity: 'high',
          file: filePath,
          line,
          column,
          codeSnippet: extractSnippet(lines, path.node),
          message: `Sensitive Express route ${displayPath} lacks authentication middleware`,
          explanation: 'Endpoints managing sensitive resources like orders, accounts, or checkout must verify user identity. Unprotected routes allow unauthorized access or privilege escalation.',
          remediation: 'Add an authentication middleware such as requireAuth or authenticate to the route chain: router.get(\'/orders\', requireAuth, handler);',
          confidence: 'high'
        });
      }
    });

    return findings;
  }
};
