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
    return {
      ast: null,
      error: new TypeError('Source code must be a string')
    };
  }

  // Reject binary files accidentally provided as source
  if (sourceCode.includes('\0')) {
    return {
      ast: null,
      error: new Error('Binary file detected (contains null bytes)')
    };
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
