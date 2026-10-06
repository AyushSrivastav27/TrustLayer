import { describe, it, expect } from 'vitest';
import { parseSource } from '../../src/engine/ast-parser.js';

describe('Engine: ast-parser (parseSource)', () => {
  it('parses valid JavaScript source code and returns a File AST with null error', () => {
    const code = 'const greeting = "hello world";';
    const { ast, error } = parseSource(code);

    expect(error).toBeNull();
    expect(ast).toBeDefined();
    expect(ast).not.toBeNull();
    expect(ast.type).toBe('File');
    expect(ast.program).toBeDefined();
    expect(ast.program.body).toHaveLength(1);
    expect(ast.program.body[0].type).toBe('VariableDeclaration');
  });

  it('correctly handles ES module syntax (import / export)', () => {
    const code = `
      import express from 'express';
      export const app = express();
      export default app;
    `;
    const { ast, error } = parseSource(code);

    expect(error).toBeNull();
    expect(ast).not.toBeNull();
    expect(ast.program.sourceType).toBe('module');
    expect(ast.program.body.some(node => node.type === 'ImportDeclaration')).toBe(true);
    expect(ast.program.body.some(node => node.type === 'ExportNamedDeclaration')).toBe(true);
    expect(ast.program.body.some(node => node.type === 'ExportDefaultDeclaration')).toBe(true);
  });

  it('correctly handles CommonJS syntax (require / module.exports)', () => {
    const code = `
      const path = require('path');
      module.exports = { path };
    `;
    const { ast, error } = parseSource(code);

    expect(error).toBeNull();
    expect(ast).not.toBeNull();
    expect(ast.program.sourceType).toBe('script');
    expect(ast.program.body).toHaveLength(2);
  });

  it('parses JSX syntax without errors', () => {
    const code = 'const component = <div className="card"><span>TrustLayer</span></div>;';
    const { ast, error } = parseSource(code);

    expect(error).toBeNull();
    expect(ast).not.toBeNull();
    const declaration = ast.program.body[0].declarations[0];
    expect(declaration.init.type).toBe('JSXElement');
  });

  it('parses modern JavaScript features (optional chaining, nullish coalescing, async/await)', () => {
    const code = `
      async function fetchUser(req) {
        const id = req?.user?.id ?? 'anonymous';
        return await getUser(id);
      }
    `;
    const { ast, error } = parseSource(code);

    expect(error).toBeNull();
    expect(ast).not.toBeNull();
    expect(ast.program.body[0].type).toBe('FunctionDeclaration');
    expect(ast.program.body[0].async).toBe(true);
  });

  it('handles empty source string gracefully', () => {
    const { ast, error } = parseSource('');

    expect(error).toBeNull();
    expect(ast).not.toBeNull();
    expect(ast.type).toBe('File');
    expect(ast.program.body).toHaveLength(0);
  });

  it('accepts optional filePath argument', () => {
    const code = 'const x = 42;';
    const { ast, error } = parseSource(code, 'src/example.js');

    expect(error).toBeNull();
    expect(ast).not.toBeNull();
  });

  it('catches invalid non-string input and returns null ast with error', () => {
    // Passing null or undefined causes babelParser.parse to throw a TypeError
    const { ast, error } = parseSource(null);

    expect(ast).toBeNull();
    expect(error).toBeInstanceOf(Error);
  });

  it('handles malformed code using errorRecovery or returning error', () => {
    // With errorRecovery: true, Babel produces an AST while attaching syntax errors to ast.errors
    const malformed = 'const x = ;';
    const result = parseSource(malformed);

    // Either errorRecovery succeeds with AST and error records, or it catches and sets error
    if (result.error) {
      expect(result.ast).toBeNull();
      expect(result.error).toBeInstanceOf(Error);
    } else {
      expect(result.ast).not.toBeNull();
      expect(result.ast.errors?.length).toBeGreaterThan(0);
    }
  });
});
