import { describe, it, expect } from 'vitest';
import { createFinding } from '../../src/types/finding.js';

describe('Types: createFinding factory', () => {
  it('creates and validates a standard finding with all required properties', () => {
    const raw = {
      ruleId: 'payment/client-controlled-amount',
      severity: 'critical',
      file: '/test/checkout.js',
      line: 42,
      codeSnippet: 'const amount = req.body.amount;',
      message: 'Client-controlled payment amount detected',
      confidence: 'high'
    };

    const finding = createFinding(raw);
    expect(finding.ruleId).toBe('payment/client-controlled-amount');
    expect(finding.severity).toBe('critical');
    expect(finding.file).toBe('/test/checkout.js');
    expect(finding.line).toBe(42);
    expect(finding.confidence).toBe('high');
  });

  it('defaults confidence to high when confidence is not provided', () => {
    const raw = {
      ruleId: 'secrets/hardcoded-secrets',
      severity: 'high',
      file: '/test/auth.js',
      line: 10,
      codeSnippet: 'const secret = "key";',
      message: 'Secret key found'
    };

    const finding = createFinding(raw);
    expect(finding.confidence).toBe('high');
  });

  it('throws an error if ruleId is missing', () => {
    expect(() => {
      createFinding({
        severity: 'critical',
        file: '/test/app.js',
        line: 1
      });
    }).toThrow('Finding requires ruleId, file, and line properties.');
  });

  it('throws an error if file is missing', () => {
    expect(() => {
      createFinding({
        ruleId: 'test/rule',
        severity: 'critical',
        line: 1
      });
    }).toThrow('Finding requires ruleId, file, and line properties.');
  });

  it('throws an error if line is not a number', () => {
    expect(() => {
      createFinding({
        ruleId: 'test/rule',
        severity: 'critical',
        file: '/test/app.js',
        line: 'first-line'
      });
    }).toThrow('Finding requires ruleId, file, and line properties.');
  });

  it('throws an error if severity is not one of critical, high, medium, low', () => {
    expect(() => {
      createFinding({
        ruleId: 'test/rule',
        severity: 'ultra-critical',
        file: '/test/app.js',
        line: 10
      });
    }).toThrow('Invalid severity "ultra-critical"');
  });

  it('throws an error if confidence is provided but invalid', () => {
    expect(() => {
      createFinding({
        ruleId: 'test/rule',
        severity: 'medium',
        file: '/test/app.js',
        line: 10,
        confidence: 'super-certain'
      });
    }).toThrow('Invalid confidence "super-certain"');
  });
});
