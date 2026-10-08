import { glob } from 'glob';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const VALID_CATEGORIES = ['secrets', 'injection', 'payment', 'auth'];

/**
 * Dynamically loads all rule definitions from src/rules/*.js
 *
 * @param {string} [rulesDir] - Path to rules folder (defaults to src/rules)
 * @returns {Promise<import('../types/rule.js').Rule[]>}
 */
export async function loadRules(rulesDir) {
  const targetDir = rulesDir || path.resolve(process.cwd(), 'src/rules');
  const ruleFiles = await glob('*.js', { cwd: targetDir, absolute: true });
  
  const rules = [];

  for (const filePath of ruleFiles) {
    try {
      const fileUrl = pathToFileURL(filePath).href;
      const module = await import(fileUrl);
      const rule = module.default;

      if (
        rule &&
        typeof rule.id === 'string' &&
        typeof rule.analyze === 'function' &&
        VALID_SEVERITIES.includes(rule.severity) &&
        VALID_CATEGORIES.includes(rule.category)
      ) {
        rules.push(rule);
      } else if (rule) {
        console.warn(`[TrustLayer] Rule at ${filePath} failed contract validation.`);
      }
    } catch (err) {
      console.warn(`Failed to load rule at ${filePath}:`, err.message);
    }
  }

  return rules;
}
