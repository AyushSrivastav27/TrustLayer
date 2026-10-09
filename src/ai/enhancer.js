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
import path from 'node:path';

export const DEFAULT_GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.5-flash';
export const GEMINI_FALLBACK_MODELS = [
  process.env.GEMINI_MODEL,
  'gemini-3.5-flash',
  'gemini-3.5-flash-lite',
  'gemini-3.6-flash',
  'gemini-3.7-flash',
  'gemini-3.8-flash',
  'gemini-3.1-flash-lite'
].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);

export const DEFAULT_CLAUDE_MODEL = process.env.CLAUDE_MODEL || process.env.ANTHROPIC_MODEL || 'claude-3-7-sonnet-latest';
export const CLAUDE_FALLBACK_MODELS = [
  process.env.CLAUDE_MODEL || process.env.ANTHROPIC_MODEL,
  'claude-3-7-sonnet-latest',
  'claude-3-5-sonnet-latest',
  'claude-3-5-haiku-latest'
].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);

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

/**
 * Deterministic, production-ready secure code remediations per rule for offline and fallback modes.
 */
const DETERMINISTIC_REMEDIATIONS = {
  'payment/payment-amount-tampering':
    '// 1. Never accept price or amount from client request payload.\n' +
    '// 2. Query price strictly from verified server-side database:\n' +
    'const product = await db.getProduct(req.body.productId);\n' +
    'const totalAmount = product.price * (req.body.quantity || 1);\n' +
    'const paymentIntent = await stripe.paymentIntents.create({\n' +
    '  amount: totalAmount,\n' +
    '  currency: "usd"\n' +
    '});',

  'payment/missing-webhook-verification':
    '// Cryptographically verify incoming webhook signature before processing:\n' +
    'const sig = req.headers["stripe-signature"];\n' +
    'let event;\n' +
    'try {\n' +
    '  event = stripe.webhooks.constructEvent(req.rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);\n' +
    '} catch (err) {\n' +
    '  return res.status(400).send(`Webhook signature verification failed: ${err.message}`);\n' +
    '}\n' +
    'if (event.type === "payment_intent.succeeded") {\n' +
    '  await fulfillOrder(event.data.object);\n' +
    '}',

  'secrets/hardcoded-secrets':
    '// Never store secrets or API keys in source code.\n' +
    '// Load securely from environment variables at runtime:\n' +
    'const JWT_SECRET = process.env.JWT_SECRET;\n' +
    'if (!JWT_SECRET) {\n' +
    '  throw new Error("FATAL: JWT_SECRET environment variable is not defined");\n' +
    '}',

  'auth/missing-auth-middleware':
    '// Protect sensitive route handlers by mounting authentication middleware:\n' +
    'import { requireAuth } from "../middleware/auth.js";\n\n' +
    '// Mount requireAuth before handler execution\n' +
    'router.get("/orders/:id", requireAuth, async (req, res) => {\n' +
    '  const order = await db.getOrder(req.params.id, req.user.id);\n' +
    '  res.json(order);\n' +
    '});',

  'injection/sql-injection':
    '// Use parameterized queries or prepared statements to prevent SQL injection:\n' +
    'const query = "SELECT * FROM products WHERE category = ? AND in_stock = ?";\n' +
    'const results = await db.all(query, [req.query.category, req.query.inStock]);',

  'injection/missing-input-validation':
    '// Validate request parameters using schema validation (e.g. Zod or Joi):\n' +
    'import { z } from "zod";\n\n' +
    'const checkoutSchema = z.object({\n' +
    '  productId: z.string().uuid(),\n' +
    '  quantity: z.number().int().positive()\n' +
    '});\n' +
    'const validated = checkoutSchema.parse(req.body);',

  'crypto/weak-crypto':
    '// Use cryptographically secure pseudo-random numbers (CSPRNG) and modern password hashing:\n' +
    'import crypto from "node:crypto";\n\n' +
    'const secureToken = crypto.randomBytes(32).toString("hex");\n' +
    'const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");'
};

export function getDeterministicScenario(ruleId) {
  return DETERMINISTIC_SCENARIOS[ruleId] || null;
}

export function getDeterministicRemediation(ruleId) {
  return DETERMINISTIC_REMEDIATIONS[ruleId] || null;
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
    const resolvedFile = path.isAbsolute(file) ? file : path.resolve(process.cwd(), file);
    if (!fsSync.existsSync(resolvedFile)) return null;
    const content = await fs.readFile(resolvedFile, 'utf-8');
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
 * Safely parses a JSON string, stripping trailing commas if necessary.
 *
 * @param {string} str
 * @returns {Object|null}
 */
function tryParseJson(str) {
  if (!str || typeof str !== 'string') return null;
  try {
    return JSON.parse(str);
  } catch {}

  // Strip trailing commas before closing braces/brackets
  try {
    const sanitized = str.replace(/,\s*([}\]])/g, '$1');
    return JSON.parse(sanitized);
  } catch {}

  return null;
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
  const direct = tryParseJson(trimmed);
  if (direct) return direct;

  // 2. Extract from markdown code fence
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (fenceMatch && fenceMatch[1]) {
    const fromFence = tryParseJson(fenceMatch[1].trim());
    if (fromFence) return fromFence;
  }

  // 3. Extract substring between first '{' and last '}'
  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    const fromBraces = tryParseJson(trimmed.slice(firstBrace, lastBrace + 1));
    if (fromBraces) return fromBraces;
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
  const defaultRemediation = DETERMINISTIC_REMEDIATIONS[finding.ruleId] || finding.remediation || '';

  const apiKey = opts.apiKey ||
    process.env.GEMINI_API_KEY ||
    process.env.GOOGLE_API_KEY ||
    process.env.ANTHROPIC_API_KEY ||
    process.env.CLAUDE_API_KEY ||
    process.env.OPENAI_API_KEY;
  const timeoutMs = opts.timeout || 15000;
  const perAttemptTimeout = Math.min(timeoutMs, 8000);

  // Base enhanced finding with deterministic offline values (including full code remediation)
  const baseEnhanced = {
    ...finding,
    aiExplanation: finding.explanation || finding.message || '',
    aiExploitScenario: defaultScenario,
    aiRemediation: defaultRemediation,
    remediation: finding.remediation || defaultRemediation,
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
    const isClaude = apiKey.startsWith('sk-ant-') || Boolean(process.env.ANTHROPIC_API_KEY) || Boolean(process.env.CLAUDE_API_KEY);
    const isGemini = !isClaude && (apiKey.startsWith('AIza') || apiKey.startsWith('AQ.') || Boolean(process.env.GEMINI_API_KEY) || Boolean(process.env.GOOGLE_API_KEY));
    const isOpenAi = !isClaude && !isGemini && (apiKey.startsWith('sk-') || Boolean(process.env.OPENAI_API_KEY));

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

    if (isClaude) {
      const candidateModels = opts.model ? [opts.model] : CLAUDE_FALLBACK_MODELS;
      for (const model of candidateModels) {
        try {
          const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': apiKey,
              'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
              model,
              max_tokens: 2048,
              messages: [{ role: 'user', content: structuredPrompt }]
            }),
            signal: AbortSignal.timeout(perAttemptTimeout)
          });

          if (response.ok) {
            const data = await response.json();
            const text = data?.content?.[0]?.text;
            const parsed = extractJsonFromResponse(text);

            if (parsed) {
              const aiData = {
                explanation: parsed.businessImpact || text.slice(0, 500),
                aiExplanation: parsed.businessImpact || text.slice(0, 500),
                aiExploitScenario: parsed.exploitScenario || defaultScenario,
                aiRemediation: parsed.remediation || defaultRemediation,
                remediation: parsed.remediation || defaultRemediation,
                aiMode: 'online',
                aiEngine: `Anthropic Claude (${model})`
              };
              LLM_CACHE.set(cacheKey, aiData);
              return {
                ...baseEnhanced,
                ...aiData
              };
            }
          }
        } catch {
          // Fall back to next model in Claude cascade
        }
      }
    } else if (isGemini) {
      const candidateModels = opts.model ? [opts.model] : GEMINI_FALLBACK_MODELS;
      for (const model of candidateModels) {
        try {
          const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
          const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: structuredPrompt }] }],
              generationConfig: {
                temperature: 0.2,
                maxOutputTokens: 2048,
                responseMimeType: 'application/json'
              }
            }),
            signal: AbortSignal.timeout(perAttemptTimeout)
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
                aiRemediation: parsed.remediation || defaultRemediation,
                remediation: parsed.remediation || defaultRemediation,
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
        } catch {
          // Fall back to next model in Gemini cascade (3.8 -> 3.7 -> 3.6 -> 3.5)
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
          max_tokens: 2048,
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
            aiRemediation: parsed.remediation || defaultRemediation,
            remediation: parsed.remediation || defaultRemediation,
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
  getDeterministicRemediation,
  enhanceFinding,
  enhanceReport,
  clearCache,
  extractJsonFromResponse,
  DEFAULT_GEMINI_MODEL,
  DEFAULT_OPENAI_MODEL,
  DETERMINISTIC_SCENARIOS,
  DETERMINISTIC_REMEDIATIONS
};
