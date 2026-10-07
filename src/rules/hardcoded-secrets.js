import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import { calculateEntropy, extractSnippet } from '../utils/ast-helpers.js';

export const rule = {
  id: 'secrets/hardcoded-secrets',
  name: 'Hardcoded Secrets or Credentials',
  severity: 'critical',
  category: 'secrets',
  description: 'Detects hardcoded API keys, JWT secrets, or high-entropy strings in source code.',
  defaultExplanation: 'Hardcoded secrets can be easily extracted from source code or version control, leading to unauthorized access.',
  defaultRemediation: 'Use environment variables (e.g., process.env.SECRET_KEY) or a secure secrets management service instead of hardcoding credentials.',
  analyze: (context) => {
    const findings = [];
    if (!context.ast) return findings;

    const SECRET_PATTERNS = [
      /apikey/i,
      /secret/i,
      /token/i,
      /password/i,
      /credential/i,
      /privatekey/i
    ];

    const isSecretIdentifier = (name) => {
      return SECRET_PATTERNS.some(regex => regex.test(name));
    };

    traverse(context.ast, {
      VariableDeclarator(path) {
        const { id, init } = path.node;
        if (id && id.name && isSecretIdentifier(id.name)) {
          if (init && init.type === 'StringLiteral') {
            const value = init.value;
            if (value.length < 5) return;
            
            const entropy = calculateEntropy(value);
            if (entropy > 3.0 || value.startsWith('sk_live_') || value.startsWith('eyJh')) {
               findings.push({
                ruleId: rule.id,
                severity: rule.severity,
                file: context.filePath,
                line: init.loc.start.line,
                column: init.loc.start.column,
                endLine: init.loc.end.line,
                codeSnippet: extractSnippet(context.lines, init),
                message: `Hardcoded secret detected in variable '${id.name}'`,
                confidence: entropy > 4.0 ? 'high' : 'medium'
              });
            }
          }
        }
      },
      AssignmentExpression(path) {
        const { left, right } = path.node;
        if (left && left.property && left.property.name && isSecretIdentifier(left.property.name)) {
           if (right && right.type === 'StringLiteral') {
            const value = right.value;
            if (value.length < 5) return;
            const entropy = calculateEntropy(value);
            if (entropy > 3.0 || value.startsWith('sk_live_') || value.startsWith('eyJh')) {
               findings.push({
                ruleId: rule.id,
                severity: rule.severity,
                file: context.filePath,
                line: right.loc.start.line,
                column: right.loc.start.column,
                endLine: right.loc.end.line,
                codeSnippet: extractSnippet(context.lines, right),
                message: `Hardcoded secret assigned to property '${left.property.name}'`,
                confidence: entropy > 4.0 ? 'high' : 'medium'
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

