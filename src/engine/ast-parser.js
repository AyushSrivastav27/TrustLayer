import * as babelParser from '@babel/parser';

/**
 * Parses source code into a Babel AST.
 *
 * @param {string} sourceCode
 * @param {string} [filePath]
 * @returns {{ ast: object|null, error: Error|null }}
 */
export function parseSource(sourceCode, filePath = '') {
  if (typeof sourceCode !== 'string') {
    return { ast: null, error: new Error('Source code must be a string') };
  }

  // Self-defense: reject binary files accidentally with JS extensions
  if (sourceCode.includes('\0')) {
    return { ast: null, error: new Error('Binary file detected: skipping AST parsing') };
  }

  try {
    const ast = babelParser.parse(sourceCode, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
      errorRecovery: true,
      sourceFilename: filePath || undefined
    });
    return { ast, error: null };
  } 
  catch (err) {
    return { ast: null, error: err };
  }
}
