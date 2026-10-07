import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import { extractSnippet } from '../utils/ast-helpers.js';

export const rule = {
  id: 'crypto/weak-crypto',
  name: 'Weak Cryptography or Insecure Randomness',
  severity: 'high',
  category: 'secrets',
  description: 'Detects use of obsolete hashing algorithms (md5, sha1) or insecure randomness (Math.random) for security tokens.',
  defaultExplanation: 'Algorithms like MD5 and SHA1 are cryptographically broken. Math.random is not cryptographically secure.',
  defaultRemediation: 'Use SHA-256 or higher for hashing, and crypto.randomBytes for generating secure tokens.',
  analyze: (context) => {
    const findings = [];
    if (!context.ast) return findings;

    traverse(context.ast, {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        
        if (
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          callee.object.name === 'crypto' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'createHash'
        ) {
          if (args.length > 0 && args[0].type === 'StringLiteral') {
            const algo = args[0].value.toLowerCase();
            if (algo === 'md5' || algo === 'sha1') {
               findings.push({
                ruleId: rule.id,
                severity: rule.severity,
                file: context.filePath,
                line: path.node.loc.start.line,
                column: path.node.loc.start.column,
                endLine: path.node.loc.end.line,
                codeSnippet: extractSnippet(context.lines, path.node),
                message: `Weak hashing algorithm used: ${algo}`,
                confidence: 'high'
              });
            }
          }
        }

        if (
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          callee.object.name === 'Math' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'random'
        ) {
          const parent = path.findParent((p) => p.isVariableDeclarator() || p.isAssignmentExpression());
          if (parent) {
            let name = '';
            if (parent.isVariableDeclarator() && parent.node.id.type === 'Identifier') {
              name = parent.node.id.name;
            } else if (parent.isAssignmentExpression() && parent.node.left.type === 'Identifier') {
              name = parent.node.left.name;
            } else if (parent.isAssignmentExpression() && parent.node.left.type === 'MemberExpression' && parent.node.left.property.type === 'Identifier') {
              name = parent.node.left.property.name;
            }
            
            if (/token|secret|key|id|session/i.test(name)) {
              findings.push({
                ruleId: rule.id,
                severity: rule.severity,
                file: context.filePath,
                line: path.node.loc.start.line,
                column: path.node.loc.start.column,
                endLine: path.node.loc.end.line,
                codeSnippet: extractSnippet(context.lines, path.node),
                message: `Insecure randomness (Math.random) used for security-sensitive variable '${name}'`,
                confidence: 'high'
              });
            }
          }
        }
      }
    });

    return findings;
  }
};

export default rule;

