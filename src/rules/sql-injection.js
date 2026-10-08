import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import * as t from '@babel/types';
import { isMethodCall, extractSnippet } from '../utils/ast-helpers.js';
import { DB_SINKS, DB_OBJECTS } from '../utils/patterns.js';

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
        const isDbCall = DB_OBJECTS.some(obj => 
          DB_SINKS.some(method => isMethodCall(path.node, obj, method))
        );


        if (isDbCall) {
          const args = path.node.arguments;
          if (!args || args.length === 0) return;

          const queryArg = args[0];

          // Check for Template Literal with expressions
          if (t.isTemplateLiteral(queryArg) && queryArg.expressions.length > 0) {
            findings.push({
              ruleId: 'injection/sql-injection',
              severity: 'critical',
              file: filePath,
              line: queryArg.loc.start.line,
              endLine: queryArg.loc.end.line,
              column: queryArg.loc.start.column,
              codeSnippet: extractSnippet(lines, queryArg),
              message: 'Potential SQL Injection: Database query uses dynamic template literal',
              confidence: 'high'
            });
          }

          // Check for String Concatenation
          if (t.isBinaryExpression(queryArg) && queryArg.operator === '+') {
            findings.push({
              ruleId: 'injection/sql-injection',
              severity: 'critical',
              file: filePath,
              line: queryArg.loc.start.line,
              endLine: queryArg.loc.end.line,
              column: queryArg.loc.start.column,
              codeSnippet: extractSnippet(lines, queryArg),
              message: 'Potential SQL Injection: Database query uses string concatenation',
              confidence: 'high'
            });
          }
        }
      }
    });

    return findings;
  }
};
