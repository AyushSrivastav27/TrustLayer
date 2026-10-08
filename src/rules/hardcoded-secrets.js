import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;
import { calculateEntropy, extractSnippet } from '../utils/ast-helpers.js';
import { SECRET_PATTERNS as KNOWN_SECRET_PATTERNS } from '../utils/patterns.js';

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
      /privatekey/i,
      /accesskey/i
    ];

    const isSecretIdentifier = (name) => {
      return SECRET_PATTERNS.some(regex => regex.test(name));
    };

    const getMatchedKnownPattern = (value) => {
      return KNOWN_SECRET_PATTERNS.find(p => p.regex.test(value));
    };


    const BENIGN_WORDS = new Set([
      'administrator',
      'admin',
      'configuration',
      'development',
      'production',
      'test',
      'testing',
      'connection',
      'application',
      'authentication',
      'authorization',
      'placeholder',
      'changeme'
    ]);

    const isBenignWord = (val) => {
      return BENIGN_WORDS.has(val.toLowerCase().trim());
    };

    const evaluateSecret = (node, value, targetName, targetType) => {
      if (typeof value !== 'string' || value.length < 5) return;

      const matchedPattern = getMatchedKnownPattern(value);
      const isSecretTarget = targetName && isSecretIdentifier(targetName);

      if (!matchedPattern && !isSecretTarget) return;

      const isPrefixSecret = value.startsWith('sk_live_') || value.startsWith('eyJh') || value.startsWith('whsec_') || value.startsWith('rzp_');
      const entropy = calculateEntropy(value);
      const isHighEntropy = (entropy >= 3.5 || (entropy > 3.2 && value.length >= 16)) && !isBenignWord(value);

      if (matchedPattern || isPrefixSecret || isHighEntropy) {
        const patternDesc = matchedPattern ? ` (${matchedPattern.name})` : '';
        const msg = targetType === 'variable'
          ? `Hardcoded secret detected in variable '${targetName || 'unknown'}'${patternDesc}`
          : `Hardcoded secret assigned to property '${targetName || 'unknown'}'${patternDesc}`;

        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          file: context.filePath,
          line: node.loc.start.line,
          column: node.loc.start.column,
          endLine: node.loc.end.line,
          codeSnippet: extractSnippet(context.lines, node),
          message: msg,
          confidence: (matchedPattern || isPrefixSecret || entropy > 4.2) ? 'high' : 'medium'
        });
      }
    };

    traverse(context.ast, {
      VariableDeclarator(path) {
        const { id, init } = path.node;
        if (init && init.type === 'StringLiteral') {
          evaluateSecret(init, init.value, id?.name, 'variable');
        }
      },
      AssignmentExpression(path) {
        const { left, right } = path.node;
        if (right && right.type === 'StringLiteral') {
          const propName = left?.property?.name || (left?.property?.value ? String(left.property.value) : '');
          evaluateSecret(right, right.value, propName, 'property');
        }
      },
      ObjectProperty(path) {
        const { key, value } = path.node;
        if (value && value.type === 'StringLiteral') {
          const keyName = key?.name || (key?.type === 'StringLiteral' ? key.value : '');
          evaluateSecret(value, value.value, keyName, 'property');
        }
      }
    });

    return findings;
  }
};

export default rule;

