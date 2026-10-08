/**
 * Additive AI Enhancement Layer for TrustLayer
 *
 * Provides contextual exploitation scenarios, remediation advice, and
 * compound attack chain correlation.
 *
 * HARD DIRECTIVE: AI is strictly additive. All static detection is 100% deterministic.
 * If offline or when no API key is configured, the enhancer falls back gracefully to
 * deterministic heuristic correlation rules without throwing errors.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';

export const DEFAULT_GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.8-flash';
export const DEFAULT_OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';

/**
 * Pre-defined heuristic attack chains for offline / zero-network environments.
 */
const KNOWN_ATTACK_PATTERNS = [
  {
    matchRules: ['payment/payment-amount-tampering', 'payment/missing-webhook-verification'],
    title: 'Arbitrary Price Manipulation & Forged Order Fulfillment',
    severity: 'critical',
    description:
      'An attacker can manipulate the checkout transaction amount to $0.01 on the client side. ' +
      'Furthermore, because incoming payment webhooks lack cryptographic HMAC signature verification, ' +
      'the attacker can forge webhook events to force order fulfillment to "completed", effectively obtaining goods for free.'
  },
  {
    matchRules: ['secrets/hardcoded-secrets', 'auth/missing-auth-middleware'],
    title: 'Administrative Impersonation & Unrestricted Endpoint Access',
    severity: 'critical',
    description:
      'With the hardcoded JWT secret or API credentials exposed in source code, an adversary can forge ' +
      'arbitrary bearer tokens with administrative privileges. Combined with missing route authentication guards, ' +
      'the adversary can access and modify internal customer and order databases.'
  },
  {
    matchRules: ['injection/sql-injection', 'injection/missing-input-validation'],
    title: 'Unauthenticated SQL Injection Leading to Database Exfiltration',
    severity: 'critical',
    description:
      'Unvalidated query parameters are passed directly into unparameterized database query execution. ' +
      'An attacker can execute arbitrary SQL injection payloads (such as UNION SELECT attacks) to dump database tables, ' +
      'bypass authorization controls, or corrupt backend data.'
  },
  {
    matchRules: ['crypto/weak-crypto'],
    title: 'Predictable Token Generation & Account Takeover',
    severity: 'high',
    description:
      'Security tokens (such as password reset tokens or session identifiers) generated with Math.random() ' +
      'or hashed with MD5 are cryptographically insecure and vulnerable to PRNG state recovery, allowing account takeover.'
  }
];

/**
 * Deterministic exploit scenarios per rule when offline or without API key.
 */
const DETERMINISTIC_SCENARIOS = {
  'payment/payment-amount-tampering':
    '1. The attacker intercepts the checkout HTTP request in an intercepting proxy (Burp Suite / OWASP ZAP).\n' +
    '2. The attacker modifies the `amount` field in the JSON payload from 9999 to 1 ($0.01).\n' +
    '3. The backend trusts the client-provided amount and forwards it directly to the payment gateway.\n' +
    '4. The transaction succeeds on the gateway, fulfilling high-value orders for fractions of a penny.',

  'payment/missing-webhook-verification':
    '1. The attacker identifies the public webhook endpoint URL (e.g. `/public/webhook`).\n' +
    '2. The attacker crafts a forged HTTP POST payload mimicking a genuine gateway payment_intent.succeeded event.\n' +
    '3. Because the endpoint does not verify the cryptographic signature header, the handler processes the request as legitimate.\n' +
    '4. The order status is updated to "PAID" in the database without any real payment having occurred.',

  'secrets/hardcoded-secrets':
    '1. An attacker discovers the hardcoded secret or credentials in repository commit history or client bundle.\n' +
    '2. Using the secret key, the attacker mints an arbitrary JSON Web Token with `{ role: "admin", sub: "root" }`.\n' +
    '3. The attacker presents this token in the `Authorization: Bearer <token>` header to bypass all authorization checks.',

  'auth/missing-auth-middleware':
    '1. An unauthenticated attacker sends a direct GET/POST request to an internal route (e.g. `/orders/:id` or `/checkout`).\n' +
    '2. Because the route handler is missing authentication middleware in its route chain, the server processes the request unconditionally.\n' +
    '3. The attacker views sensitive customer records, PII, or initiates unauthorized transactions.',

  'injection/sql-injection':
    '1. An attacker submits an SQL payload such as `\' UNION SELECT id, username, password_hash FROM users--` in an unvalidated input parameter.\n' +
    '2. The application concatenates the input directly into a dynamic template string passed to the database execution method.\n' +
    '3. The database engine executes the concatenated query, leaking password hashes or deleting database tables.',

  'injection/missing-input-validation':
    '1. An attacker supplies unexpected data types, negative quantities, or massive string payloads into request body or query parameters.\n' +
    '2. In the absence of schema validation (Zod/Joi), the unvalidated input bypasses business logic constraints.\n' +
    '3. The backend enters an unstable state, leading to denial of service, memory exhaustion, or database inconsistencies.',

  'crypto/weak-crypto':
    '1. An attacker requests a password reset token generated via `Math.random()` or hashed using MD5.\n' +
    '2. The attacker observes a sequence of pseudorandom numbers and reconstructs the internal state of the V8 PRNG.\n' +
    '3. The attacker predicts the next password reset token in advance, resetting the administrator password and taking over the account.'
};

export function getDeterministicScenario(ruleId) {
  return DETERMINISTIC_SCENARIOS[ruleId] || null;
}

/**
 * In-memory cache for LLM responses to ensure demo reliability and prevent duplicate network calls.
 */
const LLM_CACHE = new Map();

/**
 * Clears the in-memory LLM cache (useful for test resets).
 */
export function clearCache() {
  LLM_CACHE.clear();
}

/**
 * Attempts to extract surrounding code from the source file for rich context.
 *
 * @param {string} file
 * @param {number} line
 * @param {number} [windowSize=5]
 * @returns {Promise<string|null>}
 */
async function extractSurroundingCode(file, line, windowSize = 5) {
  if (!file || typeof line !== 'number' || line < 1) return null;
  try {
    if (!fsSync.existsSync(file)) return null;
    const content = await fs.readFile(file, 'utf-8');
    const lines = content.split(/\r?\n/);
    const start = Math.max(0, line - 1 - windowSize);
    const end = Math.min(lines.length, line + windowSize);
    return lines
      .slice(start, end)
      .map((l, idx) => {
        const lineNo = start + idx + 1;
        const marker = lineNo === line ? ' > ' : '   ';
        return `${marker}${String(lineNo).padStart(3, ' ')} | ${l}`;
      })
      .join('\n');
  } catch {
    return null;
  }
}

/**
 * Extracts and parses a JSON object from raw LLM output text.
 * Handles markdown fences (```json ... ```) or embedded JSON brackets.
 *
 * @param {string} rawText
 * @returns {Object|null}
 */
export function extractJsonFromResponse(rawText) {
  if (!rawText || typeof rawText !== 'string') return null;
  const trimmed = rawText.trim();

  // 1. Direct JSON parse
  try {
    return JSON.parse(trimmed);
  } catch {}

  // 2. Extract from markdown code fence
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (fenceMatch && fenceMatch[1]) {
    try {
      return JSON.parse(fenceMatch[1].trim());
    } catch {}
  }

  // 3. Extract substring between first '{' and last '}'
  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    try {
      return JSON.parse(trimmed.slice(firstBrace, lastBrace + 1));
    } catch {}
  }

  return null;
}

/**
 * Correlates multiple independent findings into high-impact composite attack chains.
 * Implements both TrustLayer ScanReport format and implementation plan AIEnhancer interface.
 *
 * @param {import('../types/finding.js').Finding[]} findings
 * @returns {import('../types/report.js').AttackChain[]}
 */
export function correlateAttackChains(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];

  const detectedRuleIds = new Set(findings.map(f => f.ruleId));
  const chains = [];

  for (const pattern of KNOWN_ATTACK_PATTERNS) {
    const isMatched = pattern.matchRules.every(ruleId => detectedRuleIds.has(ruleId));

    if (isMatched) {
      chains.push({
        title: pattern.title,
        name: pattern.title, // implementation_plan.md alias
        severity: pattern.severity,
        findingIds: pattern.matchRules,
        findings: pattern.matchRules, // implementation_plan.md alias
        description: pattern.description,
        narrative: pattern.description // implementation_plan.md alias
      });
    }
  }

  // If we have at least 2 findings but no specific chain matched, provide a general composite overview
  if (chains.length === 0 && findings.length >= 2) {
    const criticals = findings.filter(f => f.severity === 'critical');
    if (criticals.length > 0) {
      const critRuleIds = criticals.map(f => f.ruleId);
      const compositeDesc =
        'Multiple critical security flaws exist across the application boundary. An attacker can combine ' +
        'untrusted inputs with missing access controls to achieve arbitrary code or transaction manipulation.';
      chains.push({
        title: 'Composite High-Risk Vulnerability Surface',
        name: 'Composite High-Risk Vulnerability Surface',
        severity: 'critical',
        findingIds: critRuleIds,
        findings: critRuleIds,
        description: compositeDesc,
        narrative: compositeDesc
      });
    }
  }

  return chains;
}

export const generateAttackChains = correlateAttackChains;

/**
 * Enhances an individual finding with contextual exploitation scenario and remediation.
 * Supports both (finding, options) and (finding, codeContext, options) signatures.
 *
 * @param {import('../types/finding.js').Finding} finding
 * @param {string|Object} [codeContextOrOptions]
 * @param {Object} [options]
 * @returns {Promise<import('../types/finding.js').Finding>}
 */
export async function enhanceFinding(finding, codeContextOrOptions = {}, options = {}) {
  if (!finding) return finding;

  let codeContext = '';
  let opts = {};

  if (typeof codeContextOrOptions === 'string') {
    codeContext = codeContextOrOptions;
    opts = options || {};
  } else if (typeof codeContextOrOptions === 'object') {
    opts = codeContextOrOptions || {};
  }

  // Rich context resolution: caller context -> surrounding file lines -> codeSnippet
  let contextSnippet = codeContext;
  if (!contextSnippet && finding.file && typeof finding.line === 'number') {
    contextSnippet = await extractSurroundingCode(finding.file, finding.line);
  }
  if (!contextSnippet) {
    contextSnippet = finding.codeSnippet || '';
  }

  const snippet = contextSnippet.slice(0, 3000);
  const defaultScenario = DETERMINISTIC_SCENARIOS[finding.ruleId] ||
    `An attacker targets "${finding.ruleId}" by injecting malformed input into the unvalidated handler.`;

  const apiKey = opts.apiKey || process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY;
  const timeoutMs = opts.timeout || 3000;

  // Base enhanced finding with deterministic offline values
  const baseEnhanced = {
    ...finding,
    aiExplanation: finding.explanation || finding.message || '',
    aiExploitScenario: defaultScenario,
    aiRemediation: finding.remediation || '',
    aiConfidence: finding.confidence || 'high',
    confidence: finding.confidence || 'high',
    aiMode: 'offline',
    aiEngine: 'Deterministic Heuristics'
  };

  // If no LLM API key, return deterministic heuristic enhancement immediately
  if (!apiKey) {
    return baseEnhanced;
  }

  // Check cache for demo reliability
  const cacheKey = `${finding.ruleId}:${snippet.slice(0, 100)}`;
  if (LLM_CACHE.has(cacheKey)) {
    return {
      ...baseEnhanced,
      ...LLM_CACHE.get(cacheKey)
    };
  }

  // Optional online LLM call if API key provided
  try {
    const isGemini = apiKey.startsWith('AIza') || Boolean(process.env.GEMINI_API_KEY);
    const isOpenAi = !isGemini && (apiKey.startsWith('sk-') || Boolean(process.env.OPENAI_API_KEY));

    const structuredPrompt =
      `You are a principal application security engineer. Analyze this Node.js/Express security vulnerability:\n` +
      `- Rule ID: "${finding.ruleId}"\n` +
      `- Vulnerability Message: "${finding.message || ''}"\n` +
      `- Severity: "${finding.severity || ''}"\n\n` +
      `Vulnerable Code Context:\n${snippet}\n\n` +
      `Respond strictly with a valid JSON object matching this schema without any markdown formatting:\n` +
      `{\n` +
      `  "exploitScenario": "Numbered step-by-step walkthrough explaining how an attacker exploits this in production",\n` +
      `  "businessImpact": "Clear, concise impact description on financial loss, data breach, or service disruption (2-3 sentences)",\n` +
      `  "remediation": "Corrected code snippet demonstrating the secure pattern"\n` +
      `}`;

    if (isGemini) {
      const model = opts.model || DEFAULT_GEMINI_MODEL;
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: structuredPrompt }] }],
          generationConfig: {
            temperature: 0.2,
            maxOutputTokens: 800,
            responseMimeType: 'application/json'
          }
        }),
        signal: AbortSignal.timeout(timeoutMs)
      });

      if (response.ok) {
        const data = await response.json();
        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
        const parsed = extractJsonFromResponse(text);

        if (parsed) {
          const aiData = {
            explanation: parsed.businessImpact || text.slice(0, 500),
            aiExplanation: parsed.businessImpact || text.slice(0, 500),
            aiExploitScenario: parsed.exploitScenario || defaultScenario,
            aiRemediation: parsed.remediation || finding.remediation || '',
            remediation: parsed.remediation || finding.remediation || '',
            aiMode: 'online',
            aiEngine: `Google Gemini (${model})`
          };
          LLM_CACHE.set(cacheKey, aiData);
          return {
            ...baseEnhanced,
            ...aiData
          };
        }
      }
    } else if (isOpenAi) {
      const model = opts.model || DEFAULT_OPENAI_MODEL;
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model,
          messages: [{ role: 'user', content: structuredPrompt }],
          response_format: { type: 'json_object' },
          max_tokens: 800,
          temperature: 0.2
        }),
        signal: AbortSignal.timeout(timeoutMs)
      });

      if (response.ok) {
        const data = await response.json();
        const text = data?.choices?.[0]?.message?.content;
        const parsed = extractJsonFromResponse(text);

        if (parsed) {
          const aiData = {
            explanation: parsed.businessImpact || text.slice(0, 500),
            aiExplanation: parsed.businessImpact || text.slice(0, 500),
            aiExploitScenario: parsed.exploitScenario || defaultScenario,
            aiRemediation: parsed.remediation || finding.remediation || '',
            remediation: parsed.remediation || finding.remediation || '',
            aiMode: 'online',
            aiEngine: `OpenAI (${model})`
          };
          LLM_CACHE.set(cacheKey, aiData);
          return {
            ...baseEnhanced,
            ...aiData
          };
        }
      }
    }
  } catch {
    // Offline fallback on timeout, network error, rate limit, or invalid key
  }

  return baseEnhanced;
}

/**
 * Enhances an entire ScanReport with attack chains and refined findings concurrently.
 *
 * @param {import('../types/report.js').ScanReport} report
 * @param {Object} [options]
 * @returns {Promise<import('../types/report.js').ScanReport>}
 */
export async function enhanceReport(report, options = {}) {
  if (!report) return report;

  const findings = report.findings || [];
  const attackChains = correlateAttackChains(findings);

  // Parallel enhancement using Promise.all
  const enhancedFindings = await Promise.all(
    findings.map(finding => enhanceFinding(finding, options))
  );

  const anyOnline = enhancedFindings.some(f => f.aiMode === 'online');
  const aiMode = anyOnline ? 'online' : 'offline';
  const onlineEngine = enhancedFindings.find(f => f.aiMode === 'online')?.aiEngine;
  const aiEngine = anyOnline
    ? (onlineEngine || `Google Gemini (${DEFAULT_GEMINI_MODEL})`)
    : 'Deterministic Heuristics';

  return {
    ...report,
    findings: enhancedFindings,
    attackChains,
    aiMode,
    aiEngine
  };
}

export default {
  correlateAttackChains,
  generateAttackChains,
  getDeterministicScenario,
  enhanceFinding,
  enhanceReport,
  clearCache,
  extractJsonFromResponse,
  DEFAULT_GEMINI_MODEL,
  DEFAULT_OPENAI_MODEL
};
