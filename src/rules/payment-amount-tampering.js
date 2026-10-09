import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import { isReqAccess, isReqPropertyAccess, extractSnippet, unwrapNode } from '../utils/ast-helpers.js';
import { AMOUNT_KEYS, PAYMENT_SINKS, HTTP_SOURCES } from '../utils/patterns.js';

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
 * Recursively checks if a target variable was extracted from client request inputs
 * via standard, aliased, or nested destructuring (e.g. { body: { amount: customPrice } } = req).
 *
 * @param {object} pattern - Babel ObjectPattern node
 * @param {object} init - Babel expression being destructured
 * @param {string} targetVar - Name of variable being checked
 * @returns {boolean}
 */
function isVarTaintedInPattern(pattern, init, targetVar) {
  if (!pattern || !t.isObjectPattern(pattern)) return false;

  const isReqRoot = t.isIdentifier(init) && (init.name === 'req' || init.name === 'request');
  const isReqMember = isReqAccess(init);

  if (!isReqRoot && !isReqMember) return false;

  function checkPattern(pat, inHttpSource) {
    if (!t.isObjectPattern(pat)) return false;

    for (const prop of pat.properties) {
      if (!t.isObjectProperty(prop)) continue;

      const keyName = t.isIdentifier(prop.key) ? prop.key.name : (t.isStringLiteral(prop.key) ? prop.key.value : null);

      if (t.isObjectPattern(prop.value)) {
        const nextInHttpSource = inHttpSource || (isReqRoot && (keyName === 'body' || keyName === 'query' || keyName === 'params'));
        if (checkPattern(prop.value, nextInHttpSource)) {
          return true;
        }
      } else if (t.isIdentifier(prop.value)) {
        const valName = prop.value.name;
        if (valName === targetVar) {
          if (inHttpSource || isReqMember) {
            if (AMOUNT_KEYS.includes(keyName) || AMOUNT_KEYS.includes(valName)) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }

  return checkPattern(pattern, isReqMember);
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
/**
 * Recursively inspects an ObjectPattern/ArrayPattern to find how targetVarName is bound.
 * Returns an array of property keys from root init down to the variable, or null if not found.
 */
function getDestructurePath(patternNode, targetVarName, currentPath = []) {
  if (!patternNode) return null;

  if (t.isObjectPattern(patternNode)) {
    for (const prop of patternNode.properties) {
      if (t.isObjectProperty(prop)) {
        const keyName = t.isIdentifier(prop.key)
          ? prop.key.name
          : (t.isStringLiteral(prop.key) ? prop.key.value : null);

        let valueNode = prop.value;
        // Unwrap default value: { amount = 0 } or { amount: price = 0 }
        if (t.isAssignmentPattern(valueNode)) {
          valueNode = valueNode.left;
        }

        if (t.isIdentifier(valueNode)) {
          if (valueNode.name === targetVarName) {
            return [...currentPath, keyName || targetVarName];
          }
        } else if (t.isObjectPattern(valueNode) || t.isArrayPattern(valueNode)) {
          const nested = getDestructurePath(valueNode, targetVarName, [...currentPath, keyName || '']);
          if (nested) return nested;
        }
      }
    }
  }

  if (t.isArrayPattern(patternNode)) {
    for (const elem of patternNode.elements) {
      let elemNode = elem;
      if (t.isAssignmentPattern(elemNode)) {
        elemNode = elemNode.left;
      }
      if (t.isIdentifier(elemNode)) {
        if (elemNode.name === targetVarName) {
          return [...currentPath, targetVarName];
        }
      } else if (t.isObjectPattern(elemNode) || t.isArrayPattern(elemNode)) {
        const nested = getDestructurePath(elemNode, targetVarName, [...currentPath]);
        if (nested) return nested;
      }
    }
  }

  return null;
}

/**
 * Checks whether an AST node resolves to an HTTP request source (req.body, req.query, etc.).
 */
function isHttpSource(node, scope, visited = new Set()) {
  const unwrapped = unwrapNode(node);
  if (!unwrapped) return false;

  if (isReqAccess(unwrapped)) return true;

  if (t.isIdentifier(unwrapped) && scope) {
    if (visited.has(unwrapped.name)) return false;
    visited.add(unwrapped.name);

    const binding = scope.getBinding(unwrapped.name);
    if (!binding || !binding.path) return false;

    if (binding.path.isVariableDeclarator()) {
      const declNode = binding.path.node;
      const init = unwrapNode(declNode.init);

      // Direct assignment: const body = req.body;
      if (init && isHttpSource(init, binding.scope, visited)) {
        return true;
      }

      // Destructured: const { body } = req;
      if (init && t.isIdentifier(init) && init.name === 'req' && t.isObjectPattern(declNode.id)) {
        const destPath = getDestructurePath(declNode.id, unwrapped.name);
        if (destPath && destPath.length > 0 && HTTP_SOURCES.includes(destPath[0])) {
          return true;
        }
      }
    }
  }

  return false;
}

function isTaintedByClient(node, scope, visitedBindings = new Set()) {
  const unwrapped = unwrapNode(node);
  if (!unwrapped) return false;

  // Direct access: req.body, req.query, req.params, req.body.amount, etc.
  if (isReqAccess(unwrapped) || isReqPropertyAccess(unwrapped, AMOUNT_KEYS)) {
    return true;
  }

  // Bracket access: req.body['amount'] or req['body']['amount']
  if (t.isMemberExpression(unwrapped) && unwrapped.computed && t.isStringLiteral(unwrapped.property)) {
    if (isReqAccess(unwrapped.object) && AMOUNT_KEYS.includes(unwrapped.property.value)) {
      return true;
    }
    if (isReqAccess(unwrapped)) {
      return true;
    }
  }

  // Member expression on an HTTP source variable: body.amount, userReq.body.amount
  if (t.isMemberExpression(unwrapped)) {
    const propName = t.isIdentifier(unwrapped.property)
      ? unwrapped.property.name
      : (t.isStringLiteral(unwrapped.property) ? unwrapped.property.value : null);
    if (propName && AMOUNT_KEYS.includes(propName) && isHttpSource(unwrapped.object, scope)) {
      return true;
    }
  }

  // Binary expression: req.body.amount * 100, amount + 10, etc.
  if (t.isBinaryExpression(unwrapped)) {
    return (
      isTaintedByClient(unwrapped.left, scope, visitedBindings) ||
      isTaintedByClient(unwrapped.right, scope, visitedBindings)
    );
  }

  // Unary expression: +req.body.amount, -amount
  if (t.isUnaryExpression(unwrapped)) {
    return isTaintedByClient(unwrapped.argument, scope, visitedBindings);
  }

  // Type casts / wrapper calls: Number(req.body.amount), parseInt(amount), Math.round(amount)
  if (t.isCallExpression(unwrapped)) {
    return unwrapped.arguments.some(arg => isTaintedByClient(arg, scope, visitedBindings));
  }

  // Identifiers: resolve scope binding
  if (t.isIdentifier(unwrapped) && scope) {
    const varName = unwrapped.name;
    if (visitedBindings.has(varName)) return false;
    visitedBindings.add(varName);

    const binding = scope.getBinding(varName);
    if (!binding || !binding.path) return false;

    // Check function parameter destructuring: e.g. ({ body: { amount } }, res)
    if (binding.kind === 'param' && binding.path) {
      const paramNode = binding.path.node;
      if (t.isObjectPattern(paramNode)) {
        const destPath = getDestructurePath(paramNode, varName);
        if (destPath && destPath.length > 0) {
          const leafKey = destPath[destPath.length - 1];
          if (AMOUNT_KEYS.includes(leafKey) || AMOUNT_KEYS.includes(varName)) {
            return true;
          }
        }
      }
    }

    // Destructuring: const { amount } = req.body; const { amount: price } = req.body;
    // Deep destructuring: const { body: { amount } } = req;
    if (binding.path.isVariableDeclarator()) {
      const declNode = binding.path.node;
      const init = unwrapNode(declNode.init);

      if (declNode.id && (t.isObjectPattern(declNode.id) || t.isArrayPattern(declNode.id))) {
        const destPath = getDestructurePath(declNode.id, varName);
        if (destPath && destPath.length > 0) {
          const leafKey = destPath[destPath.length - 1];

          // 1. Deep destructuring directly from req: const { body: { amount } } = req;
          if (init && t.isIdentifier(init) && init.name === 'req') {
            if (HTTP_SOURCES.includes(destPath[0])) {
              if (AMOUNT_KEYS.includes(leafKey) || AMOUNT_KEYS.includes(varName)) {
                return true;
              }
            }
          }

          // 2. Destructured from an HTTP source (req.body, req.query, or variable resolving to req.body)
          if (init && isHttpSource(init, binding.scope)) {
            if (AMOUNT_KEYS.includes(leafKey) || AMOUNT_KEYS.includes(varName) || destPath.some(k => AMOUNT_KEYS.includes(k))) {
              return true;
            }
          }

          // 3. Destructured from tainted expression: const { amount } = await parseBody(...)
          if (init && isTaintedByClient(init, binding.scope, visitedBindings)) {
            if (AMOUNT_KEYS.includes(leafKey) || AMOUNT_KEYS.includes(varName)) {
              return true;
            }
          }
        }
      }

      // Direct assignment: const amount = req.body.amount; const price = amount;
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
 * Checks if an AST node represents an ID identifier or property rather than a monetary amount.
 *
 * @param {object} node - Babel AST node
 * @returns {boolean}
 */
function isIdLike(node) {
  if (!node) return false;
  if (t.isIdentifier(node)) {
    return /(?:[a-z0-9]Id|_id)$/i.test(node.name) || /^(id|paymentId|priceId|productId|orderId|customerId)$/i.test(node.name);
  }
  if (t.isMemberExpression(node)) {
    const prop = node.property;
    if (t.isIdentifier(prop)) {
      return /(?:[a-z0-9]Id|_id)$/i.test(prop.name) || /^(id|paymentId|priceId|productId|orderId|customerId)$/i.test(prop.name);
    }
    if (t.isStringLiteral(prop)) {
      return /(?:[a-z0-9]Id|_id)$/i.test(prop.value) || /^(id|paymentId|priceId|productId|orderId|customerId)$/i.test(prop.value);
    }
  }
  return false;
}

/**
 * Checks if an expression appears in a numeric context (arithmetic, unary +, or Number conversion).
 *
 * @param {object} node - Babel AST node
 * @param {object} scope - Babel Scope object
 * @returns {boolean}
 */
function isNumericContext(node, scope) {
  if (!node) return false;
  if (t.isBinaryExpression(node) && ['*', '/', '+', '-', '%'].includes(node.operator)) {
    return true;
  }
  if (t.isUnaryExpression(node) && (node.operator === '+' || node.operator === '-')) {
    return true;
  }
  if (t.isCallExpression(node)) {
    const { callee } = node;
    if (t.isIdentifier(callee) && ['Number', 'parseInt', 'parseFloat'].includes(callee.name)) {
      return true;
    }
    if (t.isMemberExpression(callee) && t.isIdentifier(callee.object) && callee.object.name === 'Math') {
      return true;
    }
  }
  if (t.isNumericLiteral(node)) {
    return true;
  }
  if (t.isIdentifier(node) && scope) {
    const binding = scope.getBinding(node.name);
    if (binding && binding.path && binding.path.isVariableDeclarator()) {
      return isNumericContext(binding.path.node.init, binding.scope);
    }
  }
  return false;
}

/**
 * Determines whether a property name and its associated value expression represent
 * an authentic monetary amount rather than a catalog/price ID.
 *
 * @param {string} propName - Name of the property in the payment call
 * @param {object} valueNode - Node representing the value assigned to the property
 * @param {object} scope - Babel Scope object
 * @returns {boolean}
 */
function isAmountProperty(propName, valueNode, scope) {
  if (!propName) return false;
  const isAmountKey = AMOUNT_KEYS.includes(propName) || propName === 'unit_amount';
  if (!isAmountKey) return false;

  // If the property is 'price', only treat as amount if used in numeric context
  // and not an explicit ID (e.g. priceId, price_id) to avoid false positives on catalog price IDs
  if (propName === 'price') {
    if (isIdLike(valueNode)) return false;
    return isNumericContext(valueNode, scope);
  }

  // Any explicit ID property is not an amount
  if (isIdLike(valueNode)) return false;

  return true;
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

          // Direct amount property: amount, price (numeric context only), total, cost, subtotal
          if (propName && isAmountProperty(propName, prop.value, scope)) {
            if (isTaintedByClient(prop.value, scope)) {
              return { isTampered: true, offendingNode: prop };
            }
          }

          // Nested structures like line_items: [{ price_data: { unit_amount: req.body.amount } }]
          // or line_items: [{ price: req.body.priceId }] (catalog price IDs ignored)
          if (t.isArrayExpression(prop.value)) {
            for (const elem of prop.value.elements) {
              if (t.isObjectExpression(elem)) {
                for (const nestedProp of elem.properties) {
                  if (t.isObjectProperty(nestedProp)) {
                    const nestedPropName = t.isIdentifier(nestedProp.key) ? nestedProp.key.name : (t.isStringLiteral(nestedProp.key) ? nestedProp.key.value : null);
                    if (t.isObjectExpression(nestedProp.value)) {
                      for (const deepProp of nestedProp.value.properties) {
                        if (t.isObjectProperty(deepProp)) {
                          const deepPropName = t.isIdentifier(deepProp.key) ? deepProp.key.name : (t.isStringLiteral(deepProp.key) ? deepProp.key.value : null);
                          if (isAmountProperty(deepPropName, deepProp.value, scope) && isTaintedByClient(deepProp.value, scope)) {
                            return { isTampered: true, offendingNode: deepProp };
                          }
                        }
                      }
                    } else if (isAmountProperty(nestedPropName, nestedProp.value, scope) && isTaintedByClient(nestedProp.value, scope)) {
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
    if (!isIdLike(arg) && isTaintedByClient(arg, scope)) {
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
              if (propName && isAmountProperty(propName, prop.value, binding.scope) && isTaintedByClient(prop.value, binding.scope)) {
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
