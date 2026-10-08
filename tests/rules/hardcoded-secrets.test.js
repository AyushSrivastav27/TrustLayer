import { describe, it, expect } from 'vitest';
import rule from '../../src/rules/hardcoded-secrets.js';
import { parseSource } from '../../src/engine/ast-parser.js';

function createTestContext(sourceCode, filePath = 'src/services/auth.js') {
  const { ast } = parseSource(sourceCode, filePath);
  return {
    filePath,
    fileContent: sourceCode,
    ast,
    lines: sourceCode.split('\n')
  };
}

describe('Rule: secrets/hardcoded-secrets', () => {
  describe('Rule Metadata', () => {
    it('should have valid metadata adhering to Rule contract', () => {
      expect(rule.id).toBe('secrets/hardcoded-secrets');
      expect(rule.name).toBeDefined();
      expect(rule.severity).toBe('critical');
      expect(rule.category).toBe('secrets');
      expect(typeof rule.analyze).toBe('function');
      expect(rule.defaultExplanation).toBeDefined();
      expect(rule.defaultRemediation).toBeDefined();
    });
  });

  describe('True Positives (Vulnerabilities Detected)', () => {
    it('should detect hardcoded API keys starting with sk_live_', () => {
      // Using string concatenation to prevent GitHub Push Protection triggers
      const fakeApiKey = ['sk', 'live', '99a8b7c6d5e4f3a2b1c0d9e8'].join('_');
      const code = `const stripeApiKey = '${fakeApiKey}';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe('secrets/hardcoded-secrets');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].line).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret detected in variable 'stripeApiKey'");
      expect(findings[0].codeSnippet).toContain(fakeApiKey);
    });

    it('should detect JWT tokens starting with eyJh', () => {
      const jwtToken = 'eyJh' + 'bGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M';
      const code = `const authToken = '${jwtToken}';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret detected in variable 'authToken'");
    });

    it('should detect high-entropy strings assigned to secret variables', () => {
      const highEntropySecret = 'x8Y@!m9Lq2Pz$kR4wT7bN^vC';
      const code = `const jwtSecret = '${highEntropySecret}';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret detected in variable 'jwtSecret'");
    });

    it('should detect secrets assigned to object properties', () => {
      const secret = 'p@ssW0rd12345!SecureKey#999';
      const code = `config.dbPassword = '${secret}';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret assigned to property 'dbPassword'");
    });

    it('should detect Razorpay keys starting with rzp_live_ or rzp_test_', () => {
      const razorpayKey = ['rzp', 'live', '12345678901234'].join('_');
      const code = `const rzpKey = '${razorpayKey}';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret");
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect AWS Access Key IDs', () => {
      const awsKey = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
      const code = `const awsAccessKey = '${awsKey}';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret");
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect Stripe Webhook Secrets starting with whsec_', () => {
      const webhookSecret = ['whsec', '1234567890abcdef12345678'].join('_');
      const code = `const webhookSecret = '${webhookSecret}';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret");
      expect(findings[0].confidence).toBe('high');
    });

    it('should detect secrets inside object literals (ObjectProperty)', () => {
      const fakeApiKey = ['sk', 'live', '1234567890abcdef12345678'].join('_');
      const code = `
        const client = new Stripe({
          apiKey: '${fakeApiKey}',
        });
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(1);
      expect(findings[0].message).toContain("Hardcoded secret assigned to property 'apiKey'");
      expect(findings[0].confidence).toBe('high');
    });
  });

  describe('True Negatives (Safe Code Ignored)', () => {
    it('should not flag environment variable usages for secrets', () => {
      const code = `
        const apiKey = process.env.STRIPE_API_KEY;
        const secret = process.env.JWT_SECRET;
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should ignore non-secret variable names even with strings', () => {
      const code = `
        const welcomeMessage = 'Welcome to our platform!';
        const username = 'john_doe';
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should ignore low-entropy or placeholder strings in secret variables', () => {
      const code = `
        const apiKey = 'test';
        const secret = 'aaaaa';
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should ignore common English dictionary words to avoid false positives (Issue M2-3)', () => {
      const code = `
        const secret = 'administrator';
        const apiKey = 'configuration';
        const token = 'development';
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should return empty findings when AST is null or missing', () => {
      const findings = rule.analyze({ filePath: 'file.txt', fileContent: '', ast: null, lines: [] });
      expect(findings).toEqual([]);
    });

    it('should ignore very short strings under 5 characters', () => {
      const code = `const token = 'abc';`;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });

    it('should ignore non-string literal initializers', () => {
      const code = `
        const token = null;
        const secret = 12345678;
        const apiKey = undefined;
      `;
      const context = createTestContext(code);

      const findings = rule.analyze(context);
      expect(findings.length).toBe(0);
    });
  });
});
