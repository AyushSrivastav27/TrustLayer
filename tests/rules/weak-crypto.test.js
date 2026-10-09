import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/weak-crypto.js';
import { parseSource } from '../../src/engine/ast-parser.js';

function createTestContext(sourceCode, filePath = 'src/services/crypto.js') {
  const { ast } = parseSource(sourceCode, filePath);
  return {
    filePath,
    fileContent: sourceCode,
    ast,
    lines: sourceCode.split('\n')
  };
}

describe('Rule: crypto/weak-crypto', () => {
  describe('Rule Metadata', () => {
    it('should have valid metadata adhering to Rule contract', () => {
      expect(rule.id).toBe('crypto/weak-crypto');
      expect(rule.name).toBeDefined();
      expect(rule.severity).toBe('high');
      expect(rule.category).toBe('secrets');
      expect(typeof rule.analyze).toBe('function');
      expect(rule.defaultExplanation).toBeDefined();
      expect(rule.defaultRemediation).toBeDefined();
    });
  });

  describe('True Positives (Vulnerabilities Detected)', () => {
    it('should detect obsolete md5 hashing algorithm', () => {
      const code = `
        const crypto = require('crypto');
        const hash = crypto.createHash('md5').update('data').digest('hex');
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe('crypto/weak-crypto');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].message).toContain('Weak hashing algorithm used: md5');
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect obsolete sha1 hashing algorithm regardless of case', () => {
      const code = `
        const hash = crypto.createHash('SHA1').update(password).digest('hex');
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('Weak hashing algorithm used: sha1');
    });

    it('should detect Math.random used for session tokens or secrets', () => {
      const code = `
        const sessionToken = Math.random().toString(36).substring(2);
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Insecure randomness (Math.random) used for security-sensitive variable 'sessionToken'");
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect Math.random assigned to object properties containing secret/key', () => {
      const code = `
        user.secretKey = Math.random();
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Insecure randomness (Math.random) used for security-sensitive variable 'secretKey'");
    });

    it('should detect Math.random used for sessionId or apiKey', () => {
      const code = `
        const sessionId = Math.random().toString(36);
        const apiKey = 'key_' + Math.random().toString(36);
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(2);
      expect(findings.some(f => f.message.includes('sessionId'))).toBe(true);
      expect(findings.some(f => f.message.includes('apiKey'))).toBe(true);
    });

    it('should detect obsolete DES cipher algorithm', () => {
      const code = `
        const cipher = crypto.createCipheriv('des-cbc', key, iv);
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('Weak cipher algorithm used: des-cbc');
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect obsolete RC4 cipher algorithm', () => {
      const code = `
        const cipher = crypto.createCipher('rc4', password);
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('Weak cipher algorithm used: rc4');
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect obsolete hashing in HMAC', () => {
      const code = `
        const hmac = crypto.createHmac('md5', secretKey).update(data).digest('hex');
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain('Weak hashing algorithm used: md5');
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect Math.random inside object properties (e.g. res.json token)', () => {
      const code = `
        res.json({ token: Math.random().toString(36) });
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Insecure randomness (Math.random) used for security-sensitive variable 'token'");
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect Math.random returned directly from a token generation function', () => {
      const code = `
        function generateSessionToken() {
          return Math.random().toString(36);
        }
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Insecure randomness (Math.random) used for security-sensitive variable 'generateSessionToken'");
      expect(findings[0].confidence).toBe('high');
    });
  });

  describe('True Negatives (Safe Code Ignored)', () => {
    it('should allow secure hashing algorithms like sha256 and sha512 and ciphers like aes-256-gcm', () => {
      const code = `
        const hash256 = crypto.createHash('sha256').update(data).digest('hex');
        const hash512 = crypto.createHash('sha512').update(data).digest('hex');
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should allow cryptographically secure random number generation', () => {
      const code = `
        const crypto = require('crypto');
        const secureToken = crypto.randomBytes(32).toString('hex');
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should allow Math.random for non-security sensitive operations', () => {
      const code = `
        const delay = Math.random() * 1000;
        const roll = Math.floor(Math.random() * 6) + 1;
        const randomPercent = Math.random();
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should ignore Math.random for benign UI and DOM identifiers (Module 2 context check)', () => {
      const code = `
        const id = '#HOT-T' + Math.floor(Math.random() * 1000);
        const elementId = '#HOT-T' + Math.floor(Math.random() * 1000);
        const tabId = 'tab-' + Math.random().toString(36);
        const cardId = 'card_' + Math.floor(Math.random() * 50);
        const randomColor = '#' + Math.floor(Math.random() * 16777215).toString(16);
        const tabKey = 'tab-' + Math.random();
        const badgeId = 'badge-' + Math.floor(Math.random() * 50);
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should ignore variables containing id as a benign substring (e.g. slider, grid, widget)', () => {
      const code = `
        const slider = Math.random();
        const grid = Math.random() * 10;
        const widget = Math.random();
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should return empty findings when AST is null', () => {
      const findings = rule.analyze({ filePath: 'file.txt', fileContent: '', ast: null, lines: [] });
      expect(findings).toEqual([]);
    });

    it('should ignore crypto.createHash called with dynamic non-string expressions', () => {
      const code = `
        const algo = getDynamicAlgorithm();
        const hash = crypto.createHash(algo);
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should ignore Math.random when not assigned to a sensitive variable', () => {
      const code = `
        function doSomething() {
          Math.random();
        }
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });
  });
});
