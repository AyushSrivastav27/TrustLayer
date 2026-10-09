import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import {
  isExpressRoute,
  getExpressRouteDetails,
  unwrapNode,
  extractSnippet
} from '../utils/ast-helpers.js';
import { DB_SINKS, DB_OBJECTS } from '../utils/patterns.js';

// Public endpoints where resource retrieval by ID is expected to be public
const PUBLIC_RESOURCE_REGEX = /(?:^|\/)(?:api\/)?(?:products?|catalog|items?|articles?|posts?|categories?|search|health|docs|public)(\/|$|\.)/i;

// Keywords indicating tenant / user ownership scoping
const OWNERSHIP_FIELD_REGEX = /\b(user_id|userId|account_id|accountId|owner_id|ownerId|customer_id|customerId|tenant_id|tenantId|created_by|createdBy)\b/i;

// Identifiers commonly used in ownership guards or middleware
const OWNERSHIP_GUARDS = ['checkownership', 'verifyownership', 'assertownership', 'isowner', 'canaccess', 'authorizegeneric'];

/**
 * Checks if a string or template contains ownership scoping conditions.
 *
 * @param {string} text
 * @returns {boolean}
 */
function hasOwnershipScopingText(text) {
  return OWNERSHIP_FIELD_REGEX.test(text);
}

/**
 * Checks if a node references an authenticated user identifier (e.g. req.user.id, user.id, req.session.userId).
 *
 * @param {object} node
 * @returns {boolean}
 */
function isUserIdentityNode(node) {
  const unwrapped = unwrapNode(node);
  if (!unwrapped) return false;

  // Direct identifier: userId, currentUserId, authUserId
  if (t.isIdentifier(unwrapped) && /^(userId|currentUserId|authUserId|loggedInUserId|reqUser)$/i.test(unwrapped.name)) {
    return true;
  }

  // MemberExpression: req.user.id, req.user._id, req.session.userId, user.id
  if (t.isMemberExpression(unwrapped)) {
    const prop = unwrapped.property;
    const propName = t.isIdentifier(prop) ? prop.name : '';
    const obj = unwrapped.object;

    if (t.isIdentifier(obj) && (obj.name === 'user' || obj.name === 'session')) {
      if (/^(id|_id|userId|sub)$/i.test(propName)) return true;
    }

    if (t.isMemberExpression(obj)) {
      const parentObj = obj.object;
      const midProp = obj.property;
      if (
        t.isIdentifier(parentObj) &&
        parentObj.name === 'req' &&
        t.isIdentifier(midProp) &&
        (midProp.name === 'user' || midProp.name === 'session' || midProp.name === 'auth')
      ) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Checks if an AST path/subtree contains an explicit ownership check (e.g. resource.userId === req.user.id).
 *
 * @param {object} handlerPath
 * @returns {boolean}
 */
function hasOwnershipCheckInHandler(handlerPath) {
  let found = false;

  handlerPath.traverse({
    BinaryExpression(binPath) {
      if (found) return;
      const op = binPath.node.operator;
      if (op === '===' || op === '==' || op === '!==' || op === '!=') {
        const left = binPath.node.left;
        const right = binPath.node.right;
        if (isUserIdentityNode(left) || isUserIdentityNode(right)) {
          found = true;
          return;
        }

        // Also check if either side accesses .user_id or .userId or .ownerId
        const isLeftOwnerField = t.isMemberExpression(left) && t.isIdentifier(left.property) && OWNERSHIP_FIELD_REGEX.test(left.property.name);
        const isRightOwnerField = t.isMemberExpression(right) && t.isIdentifier(right.property) && OWNERSHIP_FIELD_REGEX.test(right.property.name);
        if (isLeftOwnerField || isRightOwnerField) {
          found = true;
          return;
        }
      }
    },
    CallExpression(callPath) {
      if (found) return;
      const callee = unwrapNode(callPath.node.callee);
      const funcName = t.isIdentifier(callee)
        ? callee.name
        : t.isMemberExpression(callee) && t.isIdentifier(callee.property)
        ? callee.property.name
        : '';

      if (OWNERSHIP_GUARDS.some(guard => funcName.toLowerCase().includes(guard))) {
        found = true;
      }
    }
  });

  return found;
}

/**
 * Checks if a CallExpression is a database query execution.
 *
 * @param {object} node
 * @returns {boolean}
 */
function isDbQueryCall(node) {
  if (!t.isCallExpression(node)) return false;
  const callee = unwrapNode(node.callee);
  if (!t.isMemberExpression(callee)) return false;

  const propName = t.isIdentifier(callee.property) ? callee.property.name : null;
  if (!propName) return false;

  // Matches db.prepare(...).get(), db.prepare(...).all(), knex(...).where(), etc.
  if (DB_SINKS.includes(propName) || ['findById', 'findByPk', 'findOne'].includes(propName)) {
    return true;
  }

  // db.prepare(...) call
  if (t.isIdentifier(callee.object) && DB_OBJECTS.includes(callee.object.name) && propName === 'prepare') {
    return true;
  }

  return false;
}

/**
 * Checks if an AST node accesses req.params or a param variable.
 *
 * @param {object} node
 * @param {Set<string>} paramVariables
 * @returns {boolean}
 */
function usesParamId(node, paramVariables) {
  let matched = false;

  function check(n) {
    if (!n || matched) return;
    const unwrapped = unwrapNode(n);

    // Identifier declared from req.params
    if (t.isIdentifier(unwrapped) && paramVariables.has(unwrapped.name)) {
      matched = true;
      return;
    }

    // req.params.id or req.params.orderId
    if (t.isMemberExpression(unwrapped)) {
      const obj = unwrapped.object;
      if (t.isMemberExpression(obj) && t.isIdentifier(obj.object) && obj.object.name === 'req' && t.isIdentifier(obj.property) && obj.property.name === 'params') {
        matched = true;
        return;
      }
      if (t.isIdentifier(obj) && (obj.name === 'params' || paramVariables.has(obj.name))) {
        matched = true;
        return;
      }
    }

    // Call expressions like Number(req.params.id) or parseInt(id)
    if (t.isCallExpression(unwrapped)) {
      unwrapped.arguments.forEach(check);
    }

    // Array expressions: [orderId, req.user.id]
    if (t.isArrayExpression(unwrapped)) {
      unwrapped.elements.forEach(check);
    }
  }

  check(node);
  return matched;
}

/**
 * Checks if a DB call has user scoping either in its SQL text or in its arguments.
 *
 * @param {object} callNode
 * @param {object} handlerPath
 * @returns {boolean}
 */
function hasUserScopingInQuery(callNode, handlerPath) {
  // Check chaining: db.prepare('SELECT ... WHERE user_id = ?').get(...)
  let querySql = '';

  function inspectCalleeChain(n) {
    if (!n || !t.isCallExpression(n)) return;
    const unwrappedCallee = unwrapNode(n.callee);
    if (t.isMemberExpression(unwrappedCallee)) {
      const innerObj = unwrappedCallee.object;
      if (t.isCallExpression(innerObj)) {
        // inner call could be db.prepare('...')
        const args = innerObj.arguments;
        if (args && args.length > 0 && t.isStringLiteral(args[0])) {
          querySql += ' ' + args[0].value;
        }
        inspectCalleeChain(innerObj);
      }
    }
  }

  inspectCalleeChain(callNode);

  // Check direct arguments for SQL strings (e.g. db.query('SELECT ... WHERE user_id = ?', [id, req.user.id]))
  if (callNode.arguments && callNode.arguments.length > 0) {
    const firstArg = unwrapNode(callNode.arguments[0]);
    if (t.isStringLiteral(firstArg)) {
      querySql += ' ' + firstArg.value;
    } else if (t.isTemplateLiteral(firstArg)) {
      querySql += ' ' + firstArg.quasis.map(q => q.value.raw).join(' ');
    }
  }

  const sqlHasOwnership = hasOwnershipScopingText(querySql);

  // Check if query arguments pass req.user.id or a user identity
  let argsPassUser = false;
  function scanArgsForUser(args) {
    if (!args) return;
    for (const arg of args) {
      if (isUserIdentityNode(arg)) {
        argsPassUser = true;
        return;
      }
      if (t.isArrayExpression(arg)) {
        for (const el of arg.elements) {
          if (isUserIdentityNode(el)) {
            argsPassUser = true;
            return;
          }
        }
      }
    }
  }

  scanArgsForUser(callNode.arguments);

  // If query is chained, also check arguments of outer/inner calls
  if (t.isMemberExpression(callNode.callee) && t.isCallExpression(callNode.callee.object)) {
    scanArgsForUser(callNode.callee.object.arguments);
  }

  return sqlHasOwnership && argsPassUser;
}

/**
 * @typedef {import('../types/rule.js').Rule} Rule
 */

/** @type {Rule} */
export default {
  id: 'auth/idor-access-control',
  name: 'Insecure Direct Object Reference (IDOR)',
  severity: 'high',
  category: 'auth',
  description: 'Detects database queries retrieving user-owned resources by ID parameter without verifying tenant or authenticated user ownership.',
  defaultExplanation: 'Retrieving sensitive domain resources using a client-supplied identifier without scoping the database query or verifying that the requesting user owns the record enables Broken Object Level Authorization (BOLA/IDOR). Any user can view or modify records belonging to other users simply by varying the ID parameter.',
  defaultRemediation: 'Scope the database query to the authenticated user ID (e.g. WHERE id = ? AND user_id = req.user.id) or verify that the fetched resource ownership matches the authenticated user (e.g. if (record.user_id !== req.user.id) throw new ForbiddenError()).',

  analyze(context) {
    const findings = [];
    const { filePath, ast, lines } = context;

    if (!ast) return findings;

    // Skip known public resources where ID lookups are open by design (e.g. public product catalog)
    if (PUBLIC_RESOURCE_REGEX.test(filePath.replace(/\\/g, '/'))) {
      return findings;
    }

    traverse(ast, {
      CallExpression(routePath) {
        if (!isExpressRoute(routePath.node)) return;

        const routeDetails = getExpressRouteDetails(routePath.node);
        if (!routeDetails || !routeDetails.handler) return;

        const { routePath: rawPath, handler } = routeDetails;

        // Skip public subroutes
        if (rawPath && PUBLIC_RESOURCE_REGEX.test(rawPath)) {
          return;
        }

        // Intra-handler analysis
        const handlerNode = handler;
        const handlerAstPath = routePath.get('arguments.' + (routePath.node.arguments.length - 1));
        if (!handlerAstPath || (!handlerAstPath.isFunction() && !handlerAstPath.isArrowFunctionExpression())) {
          return;
        }

        // 1. Collect variables holding request parameters (req.params.id, req.params.*)
        const paramVariables = new Set();

        handlerAstPath.traverse({
          VariableDeclarator(declPath) {
            const id = declPath.node.id;
            const init = unwrapNode(declPath.node.init);

            // Direct assignment: const orderId = req.params.id
            if (t.isIdentifier(id) && init && t.isMemberExpression(init)) {
              const obj = init.object;
              if (
                (t.isMemberExpression(obj) && t.isIdentifier(obj.object) && obj.object.name === 'req' && t.isIdentifier(obj.property) && obj.property.name === 'params') ||
                (t.isIdentifier(obj) && (obj.name === 'params' || paramVariables.has(obj.name)))
              ) {
                paramVariables.add(id.name);
              }
            }

            // Destructuring: const { id } = req.params or const { id } = params
            if (t.isObjectPattern(id) && init) {
              const isReqParams =
                (t.isMemberExpression(init) && t.isIdentifier(init.object) && init.object.name === 'req' && t.isIdentifier(init.property) && init.property.name === 'params') ||
                (t.isIdentifier(init) && (init.name === 'params' || paramVariables.has(init.name)));

              if (isReqParams) {
                id.properties.forEach(prop => {
                  if (t.isObjectProperty(prop) && t.isIdentifier(prop.value)) {
                    paramVariables.add(prop.value.name);
                  }
                });
              }
            }

            // Schema parsed params: const params = orderSchema.parse(req.params)
            if (t.isIdentifier(id) && init && t.isCallExpression(init)) {
              const isParsingParams = init.arguments.some(arg => {
                const unwrapped = unwrapNode(arg);
                return (
                  t.isMemberExpression(unwrapped) &&
                  t.isIdentifier(unwrapped.object) &&
                  unwrapped.object.name === 'req' &&
                  t.isIdentifier(unwrapped.property) &&
                  unwrapped.property.name === 'params'
                );
              });
              if (isParsingParams) {
                paramVariables.add(id.name);
              }
            }

            // Wrapper casts: const orderId = Number(params.id) or parseInt(params.id)
            if (t.isIdentifier(id) && init && t.isCallExpression(init)) {
              if (usesParamId(init, paramVariables)) {
                paramVariables.add(id.name);
              }
            }
          }
        });

        // 2. Check if the handler already performs explicit ownership checks or asserts permissions
        if (hasOwnershipCheckInHandler(handlerAstPath)) {
          return;
        }

        // 3. Search for database query calls using parameter IDs without user scoping
        handlerAstPath.traverse({
          CallExpression(callPath) {
            const callNode = callPath.node;
            if (!isDbQueryCall(callNode)) return;

            // Check if any argument or chained callee uses the param ID
            const isUsingParamId =
              usesParamId(callNode, paramVariables) ||
              (t.isMemberExpression(callNode.callee) && usesParamId(callNode.callee.object, paramVariables));

            if (!isUsingParamId) return;

            // Check if query is scoped to user identity
            if (hasUserScopingInQuery(callNode, handlerAstPath)) {
              return;
            }

            // Found IDOR vulnerability!
            const loc = callNode.loc || routePath.node.loc || { start: { line: 1, column: 0 } };
            const line = loc.start.line;
            const column = loc.start.column + 1;

            findings.push({
              ruleId: 'auth/idor-access-control',
              severity: 'high',
              file: filePath,
              line,
              column,
              codeSnippet: extractSnippet(lines, callNode),
              message: 'Database query uses route parameter without scoping to authenticated user or verifying resource ownership (IDOR/BOLA)',
              explanation: 'Sensitive domain records retrieved directly via request parameters without validating that the authenticated user owns the record allows attackers to access arbitrary customer data.',
              remediation: 'Ensure the SQL query contains ownership constraints (e.g. WHERE id = ? AND user_id = req.user.id) or explicitly verify record ownership prior to dispatching responses.',
              confidence: 'high'
            });
          }
        });
      }
    });

    return findings;
  }
};
