import * as babelParser from '@babel/parser';

/**
 * Parses source code into a Babel AST.
 *
 * @param {string} sourceCode
 * @param {string} [filePath]
 * @returns {{ ast: object|null, error: Error|null }}
 */
export function parseSource(sourceCode, filePath = '') {
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
