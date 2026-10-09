#!/usr/bin/env bash
# TrustLayer Git Pre-Commit Hook
# Prevents committing code containing Critical or High security vulnerabilities.

set -e

echo "🛡️  [TrustLayer] Running pre-commit static security scan..."

# Collect staged JS/TS files excluding intentionally vulnerable demo directories and test fixtures
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|jsx|mjs|cjs|ts|tsx)$' | grep -v -E '^(demo/|tests/fixtures/)' || true)

if [ -z "$STAGED_FILES" ]; then
  echo "🛡️  [TrustLayer] No scannable staged files found. Proceeding with commit."
  exit 0
fi

FAILED=0

for FILE in $STAGED_FILES; do
  if [ -f "$FILE" ]; then
    echo "🔍 Scanning staged file: $FILE"
    if ! node src/cli.js scan "$FILE" --no-banner --fail-on high --no-report; then
      FAILED=1
    fi
  fi
done

if [ $FAILED -ne 0 ]; then
  echo ""
  echo "❌ [TrustLayer] Pre-commit security check failed."
  echo "   Vulnerabilities of high or critical severity were detected in staged changes."
  echo "   Resolve the issues above before committing."
  echo "   (Emergency bypass: git commit --no-verify)"
  exit 1
fi

echo "✅ [TrustLayer] All staged files passed static security scan."
exit 0
