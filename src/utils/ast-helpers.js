import * as t from '@babel/types';
import { HTTP_SOURCES } from './patterns.js';

/**
 * Checks if a CallExpression matches an object method call, e.g. `db.query()` or `stripe.charges.create()`.
 *
 * @param {object} node - Babel CallExpression node
 * @param {string} objectName - Name of root object (e.g. 'db', 'stripe')
 * @param {string} methodName - Method or property chain (e.g. 'query', 'create')
 * @returns {boolean}
 */
export function isMethodCall(node, objectName, methodName) {
  if (!t.isCallExpression(node)) return false;
  const { callee } = node;

  if (t.isMemberExpression(callee)) {
    // Single level: db.query(...)
    if (t.isIdentifier(callee.object) && callee.object.name === objectName) {
      if (t.isIdentifier(callee.property) && callee.property.name === methodName) {
        return true;
      }
    }

    // Two levels: stripe.charges.create(...)
    if (t.isMemberExpression(callee.object)) {
      const parentObj = callee.object;
      if (t.isIdentifier(parentObj.object) && parentObj.object.name === objectName) {
        if (t.isIdentifier(callee.property) && callee.property.name === methodName) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Checks if a CallExpression is an Express route definition (e.g. `app.post(...)`, `router.get(...)`).
 *
 * @param {object} node - Babel CallExpression node
 * @returns {boolean}
 */
export function isExpressRoute(node) {
  if (!t.isCallExpression(node)) return false;
  const { callee } = node;
  if (!t.isMemberExpression(callee)) return false;

  const validMethods = ['get', 'post', 'put', 'delete', 'patch', 'all', 'use'];
  const methodName = callee.property?.name?.toLowerCase();

  return validMethods.includes(methodName);
}

/**
 * Extracts route details (method, path, middlewares, handler) from an Express route CallExpression.
 *
 * @param {object} node - Babel CallExpression node
 * @returns {{ method: string, routePath: string|null, middlewares: object[], handler: object|null } | null}
 */
export function getExpressRouteDetails(node) {
  if (!isExpressRoute(node)) return null;

  const method = node.callee.property.name.toLowerCase();
  const args = node.arguments || [];

  if (args.length === 0) return null;

  let routePath = null;
  let handlerIndex = args.length - 1;
  let middlewareStartIndex = 0;

  if (t.isStringLiteral(args[0])) {
    routePath = args[0].value;
    middlewareStartIndex = 1;
  }

  const middlewares = args.slice(middlewareStartIndex, handlerIndex);
  const handler = args[handlerIndex] || null;

  return {
    method,
    routePath,
    middlewares,
    handler
  };
}

/**
 * Checks whether an AST node is an access to an HTTP source (e.g. `req.body`, `req.query`, `req.params`).
 *
 * @param {object} node - AST node
 * @param {string[]} [sources=HTTP_SOURCES] - List of property names to check against
 * @returns {boolean}
 */
export function isReqAccess(node, sources = HTTP_SOURCES) {
  if (!t.isMemberExpression(node)) return false;

  // Direct: req.body
  if (t.isIdentifier(node.object) && node.object.name === 'req') {
    if (t.isIdentifier(node.property) && sources.includes(node.property.name)) {
      return true;
    }
  }

  // Nested: req.body.amount
  if (t.isMemberExpression(node.object)) {
    return isReqAccess(node.object, sources);
  }

  return false;
}

/**
 * Checks if a MemberExpression node accesses a specific property on `req` (e.g. `req.body.amount`).
 *
 * @param {object} node - AST node
 * @param {string[]} propertyNames - Property names to match (e.g. ['amount', 'price'])
 * @returns {boolean}
 */
export function isReqPropertyAccess(node, propertyNames) {
  if (!t.isMemberExpression(node)) return false;
  if (!isReqAccess(node.object)) return false;

  if (t.isIdentifier(node.property)) {
    return propertyNames.includes(node.property.name);
  }

  return false;
}

/**
 * Calculates Shannon entropy of a string (useful for finding high-entropy secrets).
 *
 * @param {string} str - String to analyze
 * @returns {number} Entropy in bits per character
 */
export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;

  const frequencies = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Safely extracts the source code line for a given AST node.
 *
 * @param {string[]} lines - File lines array
 * @param {object} node - AST node with .loc
 * @returns {string} Offending source line or empty string
 */
export function extractSnippet(lines, node) {
  if (!node || !node.loc || !lines || lines.length === 0) return '';
  const lineIndex = node.loc.start.line - 1;
  return lines[lineIndex] ? lines[lineIndex].trim() : '';
}
