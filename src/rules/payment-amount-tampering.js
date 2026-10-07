import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import { isReqAccess, isReqPropertyAccess, extractSnippet } from '../utils/ast-helpers.js';
import { AMOUNT_KEYS, PAYMENT_SINKS } from '../utils/patterns.js';

/**
 * Checks if a CallExpression matches known payment SDK methods:
 * - stripe.charges.create
 * - stripe.paymentIntents.create
 * - stripe.checkout.sessions.create
 * - razorpay.orders.create
 * - razorpay.payments.capture
 * - paypal.payment.create / paypal.order.create
 *
 * @param {object} node - Babel CallExpression node
 * @returns {boolean}
 */
function isPaymentSinkCall(node) {
  if (!t.isCallExpression(node)) return false;
  const { callee } = node;

  // Single-level or two-level member expressions:
  // e.g. stripe.charges.create(...) -> callee is MemberExpression
  if (t.isMemberExpression(callee)) {
    const propName = t.isIdentifier(callee.property) ? callee.property.name : null;

    // Check against configured PAYMENT_SINKS
    for (const sink of PAYMENT_SINKS) {
      if (sink.method.includes('.')) {
        // e.g. sessions.create
        const [subProp, subMethod] = sink.method.split('.');
        if (propName === subMethod && t.isMemberExpression(callee.object)) {
          const midObj = callee.object;
          if (t.isIdentifier(midObj.property) && midObj.property.name === subProp) {
            if (t.isMemberExpression(midObj.object)) {
              const rootObj = midObj.object.object;
              if (t.isIdentifier(rootObj) && rootObj.name === sink.object) {
                return true;
              }
            }
          }
        }
      } else {
        // e.g. stripe.charges.create or razorpay.orders.create
        if (propName === sink.method && t.isMemberExpression(callee.object)) {
          const midObj = callee.object;
          if (t.isIdentifier(midObj.property) && midObj.property.name === sink.property) {
            if (t.isIdentifier(midObj.object) && midObj.object.name === sink.object) {
              return true;
            }
          }
        }
      }
    }

    // Generic fallback for payment calls like stripe.charges.create, paymentGateway.createCharge, etc.
    if (propName === 'create' || propName === 'capture') {
      if (t.isMemberExpression(callee.object)) {
        const midName = callee.object.property?.name;
        if (['charges', 'paymentIntents', 'orders', 'payments', 'sessions'].includes(midName)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Checks if a given AST expression is tainted by client-controlled request input.
 * Recursively resolves variables within the local scope.
 *
 * @param {object} node - AST node to inspect
 * @param {object} scope - Babel Scope object
 * @param {Set<string>} visitedBindings - Recursion guard for variable tracking
 * @returns {boolean}
 */
function isTaintedByClient(node, scope, visitedBindings = new Set()) {
  if (!node) return false;

  // Direct access: req.body, req.query, req.params, req.body.amount, etc.
  if (isReqAccess(node) || isReqPropertyAccess(node, AMOUNT_KEYS)) {
    return true;
  }

  // Bracket access: req.body['amount'] or req['body']['amount']
  if (t.isMemberExpression(node) && node.computed && t.isStringLiteral(node.property)) {
    if (isReqAccess(node.object) && AMOUNT_KEYS.includes(node.property.value)) {
      return true;
    }
    if (isReqAccess(node)) {
      return true;
    }
  }

  // Binary expression: req.body.amount * 100, amount + 10, etc.
  if (t.isBinaryExpression(node)) {
    return (
      isTaintedByClient(node.left, scope, visitedBindings) ||
      isTaintedByClient(node.right, scope, visitedBindings)
    );
  }

  // Unary expression: +req.body.amount, -amount
  if (t.isUnaryExpression(node)) {
    return isTaintedByClient(node.argument, scope, visitedBindings);
  }

  // Type casts / wrapper calls: Number(req.body.amount), parseInt(amount), Math.round(amount)
  if (t.isCallExpression(node)) {
    return node.arguments.some(arg => isTaintedByClient(arg, scope, visitedBindings));
  }

  // Identifiers: resolve scope binding
  if (t.isIdentifier(node) && scope) {
    const varName = node.name;
    if (visitedBindings.has(varName)) return false;
    visitedBindings.add(varName);

    const binding = scope.getBinding(varName);
    if (!binding || !binding.path) return false;

    // Destructuring: const { amount } = req.body; or const { price: userPrice } = req.body;
    if (binding.path.isVariableDeclarator()) {
      const declNode = binding.path.node;
      const init = declNode.init;

      if (t.isObjectPattern(declNode.id)) {
        // Check if init is an HTTP source (e.g. req.body)
        if (isReqAccess(init)) {
          // If the variable was destructured from req.body/req.query with an amount key
          for (const prop of declNode.id.properties) {
            if (t.isObjectProperty(prop)) {
              const keyName = t.isIdentifier(prop.key) ? prop.key.name : (t.isStringLiteral(prop.key) ? prop.key.value : null);
              const valName = t.isIdentifier(prop.value) ? prop.value.name : null;
              if (valName === varName && (AMOUNT_KEYS.includes(keyName) || AMOUNT_KEYS.includes(varName))) {
                return true;
              }
            }
          }
        }
      }

      // Direct assignment: const amount = req.body.amount;
      if (init) {
        if (isTaintedByClient(init, binding.scope, visitedBindings)) {
          return true;
        }
      }

      // Check constantViolations (reassignments like amount = req.body.amount)
      if (binding.constantViolations && binding.constantViolations.length > 0) {
        for (const assignPath of binding.constantViolations) {
          if (assignPath.isAssignmentExpression()) {
            if (isTaintedByClient(assignPath.node.right, assignPath.scope, visitedBindings)) {
              return true;
            }
          }
        }
      }
    }
  }

  return false;
}

/**
 * Inspects arguments passed to a payment sink call to find client-controlled amounts.
 *
 * @param {object} callNode - Babel CallExpression node
 * @param {object} scope - Babel Scope object
 * @returns {{ isTampered: boolean, offendingNode: object|null }}
 */
function inspectPaymentSinkArguments(callNode, scope) {
  const args = callNode.arguments || [];
  if (args.length === 0) return { isTampered: false, offendingNode: null };

  // Inspect each argument
  for (const arg of args) {
    // 1. Object literal argument: { amount: req.body.amount, currency: 'usd' }
    if (t.isObjectExpression(arg)) {
      for (const prop of arg.properties) {
        if (t.isObjectProperty(prop)) {
          const propName = t.isIdentifier(prop.key) ? prop.key.name : (t.isStringLiteral(prop.key) ? prop.key.value : null);

          // Direct amount property: amount, price, total, cost, subtotal
          if (propName && AMOUNT_KEYS.includes(propName)) {
            if (isTaintedByClient(prop.value, scope)) {
              return { isTampered: true, offendingNode: prop };
            }
          }

          // Nested structures like line_items: [{ price_data: { unit_amount: req.body.amount } }]
          if (t.isArrayExpression(prop.value)) {
            for (const elem of prop.value.elements) {
              if (t.isObjectExpression(elem)) {
                for (const nestedProp of elem.properties) {
                  if (t.isObjectProperty(nestedProp)) {
                    if (t.isObjectExpression(nestedProp.value)) {
                      for (const deepProp of nestedProp.value.properties) {
                        if (t.isObjectProperty(deepProp) && isTaintedByClient(deepProp.value, scope)) {
                          return { isTampered: true, offendingNode: deepProp };
                        }
                      }
                    } else if (isTaintedByClient(nestedProp.value, scope)) {
                      return { isTampered: true, offendingNode: nestedProp };
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    // 2. Direct amount identifier or expression: razorpay.payments.capture(id, req.body.amount)
    if (isTaintedByClient(arg, scope)) {
      return { isTampered: true, offendingNode: arg };
    }

    // 3. Identifier pointing to an options object: const opts = { amount: req.body.amount }; stripe.charges.create(opts)
    if (t.isIdentifier(arg) && scope) {
      const binding = scope.getBinding(arg.name);
      if (binding && binding.path && binding.path.isVariableDeclarator()) {
        const init = binding.path.node.init;
        if (t.isObjectExpression(init)) {
          for (const prop of init.properties) {
            if (t.isObjectProperty(prop)) {
              const propName = t.isIdentifier(prop.key) ? prop.key.name : (t.isStringLiteral(prop.key) ? prop.key.value : null);
              if (propName && AMOUNT_KEYS.includes(propName) && isTaintedByClient(prop.value, binding.scope)) {
                return { isTampered: true, offendingNode: prop };
              }
            }
          }
        }
      }
    }
  }

  return { isTampered: false, offendingNode: null };
}

export default {
  id: 'payment/payment-amount-tampering',
  name: 'Payment Amount Tampering',
  severity: 'critical',
  category: 'payment',
  description: 'Detects client-controlled payment amounts passed directly to payment gateway SDKs.',
  defaultExplanation: 'Payment amounts must always be calculated or retrieved on the server from an authoritative data store (e.g. database or catalog). Allowing clients to supply or modify the transaction amount directly via request parameters enables attackers to purchase items for arbitrary, zero, or negative prices.',
  defaultRemediation: 'Calculate the order total server-side by looking up catalog item prices in your database. Pass the server-calculated amount to the payment gateway (e.g. stripe.paymentIntents.create({ amount: calculatedTotal })) rather than trusting req.body.amount.',

  /**
   * Analyzes an AST for payment amount tampering vulnerabilities.
   *
   * @param {import('../types/rule.js').AnalysisContext} context
   * @returns {import('../types/finding.js').Finding[]}
   */
  analyze(context) {
    const findings = [];
    const { filePath, ast, lines } = context;
    if (!ast) return findings;

    traverse(ast, {
      CallExpression(path) {
        if (!isPaymentSinkCall(path.node)) return;

        const { isTampered, offendingNode } = inspectPaymentSinkArguments(path.node, path.scope);
        if (isTampered) {
          const targetNode = offendingNode || path.node;
          const line = targetNode.loc ? targetNode.loc.start.line : (path.node.loc ? path.node.loc.start.line : 1);
          const column = targetNode.loc ? targetNode.loc.start.column + 1 : (path.node.loc ? path.node.loc.start.column + 1 : 1);

          findings.push({
            ruleId: 'payment/payment-amount-tampering',
            severity: 'critical',
            file: filePath,
            line,
            column,
            codeSnippet: extractSnippet(lines, targetNode) || extractSnippet(lines, path.node),
            message: 'Client-controlled payment amount detected flowing into payment processing call',
            explanation: 'Payment amounts must always be calculated or retrieved on the server from an authoritative data store. Trusting client-supplied amounts allows price tampering attacks.',
            remediation: 'Retrieve verified item prices from your database on the server and calculate the total server-side before initiating payment.',
            confidence: 'high'
          });
        }
      }
    });

    return findings;
  }
};
