import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import { getExpressRouteDetails, isReqAccess, extractSnippet } from '../utils/ast-helpers.js';

export default {
  id: 'injection/missing-input-validation',
  name: 'Missing Input Validation',
  severity: 'high',
  category: 'injection',
  description: 'Detects Express route handlers that process user input without validating it.',
  defaultExplanation: 'Taking data directly from req.body, req.query, or req.params without validation can lead to injection attacks, logic bypass, or crashes. Input should always be validated against a strict schema.',
  defaultRemediation: 'Use a validation library like Zod, Joi, or express-validator to define and enforce input schemas before processing the data.',

  analyze(context) {
    const findings = [];
    const { filePath, ast, lines } = context;

    if (!ast) return findings;

    traverse(ast, {
      CallExpression(path) {
        const route = getExpressRouteDetails(path.node);
        if (!route || !route.handler) return;

        // Ensure the handler is a function
        if (!t.isFunctionExpression(route.handler) && !t.isArrowFunctionExpression(route.handler)) return;

        let hasInputAccess = false;
        let hasValidation = false;
        let inputAccessNode = null;

        const handlerPath = path.get('arguments').find(p => p.node === route.handler);
        if (!handlerPath) return;

        // Traverse inside the handler
        handlerPath.traverse({
          MemberExpression(innerPath) {
            if (isReqAccess(innerPath.node)) {
              hasInputAccess = true;
              if (!inputAccessNode) {
                inputAccessNode = innerPath.node;
              }
            }
          },
          UnaryExpression(innerPath) {
            if (innerPath.node.operator === 'typeof') {
              hasValidation = true;
            } else if (innerPath.node.operator === '!') {
              if (t.isMemberExpression(innerPath.node.argument) && isReqAccess(innerPath.node.argument)) {
                hasValidation = true;
              }
            }
          },
          CallExpression(innerPath) {
            const callee = innerPath.node.callee;
            // Rough heuristic: if it calls .validate(), .parse(), .safeParse(), or uses express-validator like body()
            if (t.isMemberExpression(callee)) {
              if (t.isIdentifier(callee.property)) {
                const name = callee.property.name;
                if (['validate', 'parse', 'safeParse'].includes(name)) {
                  hasValidation = true;
                }
              }
            } else if (t.isIdentifier(callee)) {
               const name = callee.name;
               if (['body', 'query', 'param', 'check', 'validationResult'].includes(name)) {
                  hasValidation = true;
               }
            }
          }
        });

        // Also check if any middleware looks like a validator (e.g., validate(schema))
        route.middlewares.forEach(mw => {
          if (t.isCallExpression(mw)) {
            if (t.isIdentifier(mw.callee) && (mw.callee.name.includes('validate') || mw.callee.name.includes('check'))) {
              hasValidation = true;
            }
          }
        });

        if (hasInputAccess && !hasValidation) {
          findings.push({
            ruleId: 'injection/missing-input-validation',
            severity: 'high',
            file: filePath,
            line: route.handler.loc.start.line,
            endLine: route.handler.loc.end.line,
            column: route.handler.loc.start.column,
            codeSnippet: extractSnippet(lines, inputAccessNode),
            message: 'Route accesses user input (req.body/query/params) but lacks apparent validation.',
            confidence: 'low'
          });
        }
      }
    });

    return findings;
  }
};
