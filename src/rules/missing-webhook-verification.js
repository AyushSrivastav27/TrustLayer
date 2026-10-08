import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import { isExpressRoute, getExpressRouteDetails, extractSnippet } from '../utils/ast-helpers.js';
import { WEBHOOK_VERIFIERS, NON_EXPRESS_OBJECTS } from '../utils/patterns.js';

const WEBHOOK_PATH_REGEX = /\/(webhook|stripe-webhook|payment-webhook|callback|ipn|notify)(\/|$)/i;
const VERIFICATION_FUNC_REGEX = /(constructEvent|timingSafeEqual|verifyPaymentSignature|validateWebhookSignature|verifySignature|validateSignature|createHmac|verifyWebhook)/i;

/**
 * Checks if a CallExpression represents a signature/HMAC verification call.
 *
 * @param {object} node - Babel CallExpression node
 * @returns {boolean}
 */
function isVerificationCall(node) {
  if (!t.isCallExpression(node)) return false;
  const { callee } = node;

  // Direct function call: constructEvent(...), timingSafeEqual(...)
  if (t.isIdentifier(callee)) {
    if (WEBHOOK_VERIFIERS.includes(callee.name) || VERIFICATION_FUNC_REGEX.test(callee.name)) {
      return true;
    }
  }

  // Member expression: stripe.webhooks.constructEvent, crypto.timingSafeEqual, etc.
  if (t.isMemberExpression(callee)) {
    const propName = t.isIdentifier(callee.property) ? callee.property.name : null;
    if (propName && (WEBHOOK_VERIFIERS.includes(propName) || VERIFICATION_FUNC_REGEX.test(propName))) {
      return true;
    }

    // Two-level: stripe.webhooks.constructEvent
    if (t.isMemberExpression(callee.object)) {
      const midProp = callee.object.property?.name;
      if (midProp === 'webhooks' && propName === 'constructEvent') {
        return true;
      }
    }
  }

  return false;
}

/**
 * Checks if an AST subtree (e.g. function body) contains any signature verification calls.
 *
 * @param {object} rootNode - Root AST node of the handler
 * @returns {boolean}
 */
function containsSignatureVerification(rootNode) {
  if (!rootNode) return false;

  let verified = false;

  // If rootNode is a function or block, traverse its children
  traverse(rootNode, {
    noScope: true,
    CallExpression(subPath) {
      if (isVerificationCall(subPath.node)) {
        verified = true;
        subPath.stop();
      }
    }
  });

  return verified;
}

/**
 * Checks if any middleware argument contains a signature verification function.
 *
 * @param {object[]} middlewares - Array of AST middleware nodes
 * @returns {boolean}
 */
function hasVerificationMiddleware(middlewares) {
  if (!middlewares || middlewares.length === 0) return false;

  for (const mw of middlewares) {
    if (t.isIdentifier(mw) && VERIFICATION_FUNC_REGEX.test(mw.name)) {
      return true;
    }
    if (t.isCallExpression(mw)) {
      if (isVerificationCall(mw)) return true;
      const callee = mw.callee;
      if (t.isIdentifier(callee) && VERIFICATION_FUNC_REGEX.test(callee.name)) {
        return true;
      }
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && VERIFICATION_FUNC_REGEX.test(callee.property.name)) {
        return true;
      }
    }
  }

  return false;
}


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
  id: 'payment/missing-webhook-verification',
  name: 'Missing Webhook Signature Verification',
  severity: 'high',
  category: 'payment',
  description: 'Detects webhook route handlers that process events without cryptographic signature verification.',
  defaultExplanation: 'Webhook endpoints process asynchronous events from payment gateways (e.g., Stripe, Razorpay) that trigger critical actions like fulfilling orders or crediting accounts. Without verifying the HMAC cryptographic signature on incoming requests, an attacker can send forged webhook payloads to mark unpaid orders as fulfilled.',
  defaultRemediation: 'Verify the webhook signature using the payment gateway SDK (e.g. stripe.webhooks.constructEvent(req.body, sig, endpointSecret)) or crypto.timingSafeEqual before processing event payloads.',

  /**
   * Analyzes an AST for missing webhook signature verification.
   *
   * @param {import('../types/rule.js').AnalysisContext} context
   * @returns {import('../types/finding.js').Finding[]}
   */
  analyze(context) {
    const findings = [];
    const { filePath, ast, lines } = context;
    if (!ast) return findings;

    const normalizedPath = filePath.replace(/\\/g, '/');
    const isWebhookFile = /(?:^|\/)(?:routes?\/)?webhook(\.|\/|$)/i.test(normalizedPath);

    traverse(ast, {
      CallExpression(path) {
        if (!isExpressRoute(path.node)) return;

        const details = getExpressRouteDetails(path.node);
        if (!isValidExpressRoute(path.node, details)) return;

        const { method, routePath, middlewares, handler } = details;

        // Webhooks primarily listen on POST (or PUT / ALL)
        if (!['post', 'all', 'put'].includes(method)) return;

        // Check whether this route represents a webhook endpoint
        const isWebhookRoute =
          (routePath && (WEBHOOK_PATH_REGEX.test(routePath) || /webhook/i.test(routePath))) ||
          isWebhookFile;

        if (!isWebhookRoute) return;

        // 1. Check if verification is performed in route middleware
        if (hasVerificationMiddleware(middlewares)) {
          return;
        }

        // 2. Check if verification is performed in handler body
        let handlerNode = handler;

        // If handler is an identifier (e.g. router.post('/webhook', handleWebhook))
        if (t.isIdentifier(handler) && path.scope) {
          const binding = path.scope.getBinding(handler.name);
          if (binding && binding.path) {
            if (binding.path.isFunctionDeclaration()) {
              handlerNode = binding.path.node;
            } else if (binding.path.isVariableDeclarator()) {
              handlerNode = binding.path.node.init;
            }
          }
        }

        if (handlerNode && containsSignatureVerification(handlerNode)) {
          return;
        }

        // Flag missing webhook verification
        const line = path.node.loc ? path.node.loc.start.line : 1;
        const column = path.node.loc ? path.node.loc.start.column + 1 : 1;
        const displayPath = routePath ? `"${routePath}"` : `handler in ${filePath}`;

        findings.push({
          ruleId: 'payment/missing-webhook-verification',
          severity: 'high',
          file: filePath,
          line,
          column,
          codeSnippet: extractSnippet(lines, path.node),
          message: `Webhook endpoint ${displayPath} does not verify incoming webhook signature`,
          explanation: 'Webhook endpoints must verify the provider cryptographic signature before processing events. Failure to verify signatures allows attackers to forge payment events and trigger unauthorized order fulfillment.',
          remediation: 'Use stripe.webhooks.constructEvent(req.body, sig, webhookSecret) or crypto.timingSafeEqual to verify the webhook signature before taking any action.',
          confidence: 'high'
        });
      }
    });

    return findings;
  }
};
