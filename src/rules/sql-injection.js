import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import { isMethodCall, extractSnippet, unwrapNode } from '../utils/ast-helpers.js';
import { DB_SINKS, DB_OBJECTS } from '../utils/patterns.js';

function isDbSinkCall(node) {
  if (!t.isCallExpression(node)) return false;
  const callee = unwrapNode(node.callee);
  if (!t.isMemberExpression(callee)) return false;

  const propName = t.isIdentifier(callee.property) ? callee.property.name : null;
  if (!propName || !DB_SINKS.includes(propName)) return false;

  // Single-level: db.query(...), knex.raw(...), prisma.$queryRawUnsafe(...)
  if (t.isIdentifier(callee.object)) {
    return DB_OBJECTS.includes(callee.object.name);
  }

  // Chained / member: this.db.query(...), app.locals.db.query(...), sequelize.query(...)
  if (t.isMemberExpression(callee.object)) {
    const midProp = t.isIdentifier(callee.object.property) ? callee.object.property.name : null;
    if (midProp && DB_OBJECTS.includes(midProp)) {
      return true;
    }
    const rootObj = callee.object.object;
    if (t.isIdentifier(rootObj) && DB_OBJECTS.includes(rootObj.name)) {
      return true;
    }
  }

  // Fallback to isMethodCall check across DB_OBJECTS
  return DB_OBJECTS.some(obj => isMethodCall(node, obj, propName));
}

export default {
  id: 'injection/sql-injection',
  name: 'SQL Injection',
  severity: 'critical',
  category: 'injection',
  description: 'Detects unsanitized user input passed directly to database query execution methods.',
  defaultExplanation: 'Concatenating strings or using template literals with dynamic expressions in database queries allows attackers to alter the query logic, leading to data breach or unauthorized modification.',
  defaultRemediation: 'Use parameterized queries or prepared statements provided by your database driver instead of string interpolation.',

  analyze(context) {
    const findings = [];
    const { filePath, ast, lines } = context;

    if (!ast) return findings;

    traverse(ast, {
      CallExpression(path) {
        if (!isDbSinkCall(path.node)) return;

        const args = path.node.arguments;
        if (!args || args.length === 0) return;

        let targetArg = unwrapNode(args[0]);
        const locNode = targetArg;

        // Trace variable identifier to its declaration if defined locally
        if (t.isIdentifier(targetArg) && path.scope) {
          const binding = path.scope.getBinding(targetArg.name);
          if (binding && binding.path && binding.path.isVariableDeclarator()) {
            const init = unwrapNode(binding.path.node.init);
            if (init && (t.isTemplateLiteral(init) || t.isBinaryExpression(init))) {
              targetArg = init;
            }
          }
        }

        // Check for Template Literal with expressions
        if (t.isTemplateLiteral(targetArg) && targetArg.expressions.length > 0) {
          findings.push({
            ruleId: 'injection/sql-injection',
            severity: 'critical',
            file: filePath,
            line: locNode.loc ? locNode.loc.start.line : path.node.loc.start.line,
            endLine: locNode.loc ? locNode.loc.end.line : path.node.loc.end.line,
            column: locNode.loc ? locNode.loc.start.column : path.node.loc.start.column,
            codeSnippet: extractSnippet(lines, locNode) || extractSnippet(lines, path.node),
            message: 'Potential SQL Injection: Database query uses dynamic template literal',
            confidence: 'high'
          });
        }

        // Check for String Concatenation
        if (t.isBinaryExpression(targetArg) && targetArg.operator === '+') {
          findings.push({
            ruleId: 'injection/sql-injection',
            severity: 'critical',
            file: filePath,
            line: locNode.loc ? locNode.loc.start.line : path.node.loc.start.line,
            endLine: locNode.loc ? locNode.loc.end.line : path.node.loc.end.line,
            column: locNode.loc ? locNode.loc.start.column : path.node.loc.start.column,
            codeSnippet: extractSnippet(lines, locNode) || extractSnippet(lines, path.node),
            message: 'Potential SQL Injection: Database query uses string concatenation',
            confidence: 'high'
          });
        }
      }
    });

    return findings;
  }
};
