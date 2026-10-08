import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import { extractSnippet } from '../utils/ast-helpers.js';
import { WEAK_HASH_ALGORITHMS } from '../utils/patterns.js';

export const rule = {
  id: 'crypto/weak-crypto',
  name: 'Weak Cryptography or Insecure Randomness',
  severity: 'high',
  category: 'secrets',
  description: 'Detects use of obsolete hashing algorithms (md5, sha1), weak ciphers (des, rc4), or insecure randomness (Math.random) for security tokens.',
  defaultExplanation: 'Algorithms like MD5, SHA1, DES, and RC4 are cryptographically broken. Math.random is not cryptographically secure.',
  defaultRemediation: 'Use SHA-256 or higher for hashing, AES-GCM for encryption, and crypto.randomBytes for generating secure tokens.',
  analyze: (context) => {
    const findings = [];
    if (!context.ast) return findings;

    const HASH_METHODS = ['createHash', 'createHmac'];
    const CIPHER_METHODS = ['createCipher', 'createCipheriv', 'createDecipher', 'createDecipheriv'];

    traverse(context.ast, {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        
        if (
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          callee.object.name === 'crypto' &&
          callee.property.type === 'Identifier'
        ) {
          const methodName = callee.property.name;

          if (HASH_METHODS.includes(methodName) && args.length > 0 && args[0].type === 'StringLiteral') {
            const algo = args[0].value.toLowerCase();
            if (algo === 'md5' || algo === 'sha1' || algo.startsWith('md5') || algo.startsWith('sha1')) {
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

          if (CIPHER_METHODS.includes(methodName) && args.length > 0 && args[0].type === 'StringLiteral') {
            const algo = args[0].value.toLowerCase();
            if (
              WEAK_HASH_ALGORITHMS.includes(algo) ||
              algo.startsWith('des') ||
              algo.startsWith('rc4')
            ) {
              findings.push({
                ruleId: rule.id,
                severity: rule.severity,
                file: context.filePath,
                line: path.node.loc.start.line,
                column: path.node.loc.start.column,
                endLine: path.node.loc.end.line,
                codeSnippet: extractSnippet(context.lines, path.node),
                message: `Weak cipher algorithm used: ${algo}`,
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
          const parent = path.findParent((p) =>
            p.isVariableDeclarator() ||
            p.isAssignmentExpression() ||
            p.isObjectProperty() ||
            p.isReturnStatement()
          );
          if (parent) {
            let name = '';
            if (parent.isVariableDeclarator() && parent.node.id.type === 'Identifier') {
              name = parent.node.id.name;
            } else if (parent.isAssignmentExpression() && parent.node.left.type === 'Identifier') {
              name = parent.node.left.name;
            } else if (parent.isAssignmentExpression() && parent.node.left.type === 'MemberExpression' && parent.node.left.property.type === 'Identifier') {
              name = parent.node.left.property.name;
            } else if (parent.isObjectProperty()) {
              if (parent.node.key.type === 'Identifier') {
                name = parent.node.key.name;
              } else if (parent.node.key.type === 'StringLiteral') {
                name = parent.node.key.value;
              }
            } else if (parent.isReturnStatement()) {
              const funcParent = path.getFunctionParent();
              name = funcParent?.node?.id?.name || funcParent?.parentPath?.node?.id?.name || '';
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

