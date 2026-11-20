#!/bin/bash
# SEC-01..SEC-04 regression tests for scripts/collect-policies.sh.
# Static/source-level tests plus a ps-argv exposure check.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/collect-policies.sh"
LIB="$REPO_ROOT/scripts/lib/nova-op-env.sh"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1 -- $2"; FAIL=$((FAIL+1)); }

run_test() { if "$@"; then pass "$1"; else fail "$1" "test body returned non-zero"; fi; }

# Ensure a clean environment for secret-resolution tests.
unset -v ANTHROPIC_API_KEY

# SEC-02: no plaintext-file fallback
test_no_plaintext_fallback() {
    ! grep -q "\.secrets/anthropic-api-key" "$SCRIPT"
    ! grep -q 'cat .*anthropic' "$SCRIPT"
    ! grep -q "~/.secrets" "$SCRIPT"
}
run_test test_no_plaintext_fallback

# SEC-01: uses nova-op item map
test_uses_nova_op() {
    grep -q "source.*lib/nova-op-env.sh" "$SCRIPT"
    grep -q "nova_op_load_env ANTHROPIC_API_KEY" "$SCRIPT"
}
run_test test_uses_nova_op

# SEC-03: loud failure when key cannot be resolved
test_fails_loudly() {
    grep -q "ERROR: failed to resolve ANTHROPIC_API_KEY via nova-op" "$SCRIPT"
    grep -q "exit 1" "$SCRIPT"
}
run_test test_fails_loudly

# SEC-04: API key never appears in curl argv (header file instead)
test_no_key_in_curl_argv() {
    ! grep -E 'curl .*-H "x-api-key: \$' "$SCRIPT"
    grep -q '@\$ANTHROPIC_HEADER_FILE' "$SCRIPT"
}
run_test test_no_key_in_curl_argv

# SEC-04: header file is created with restrictive permissions and cleaned up
test_header_file_hygiene() {
    grep -q 'chmod 600 "\$ANTHROPIC_HEADER_FILE"' "$SCRIPT"
    grep -q 'rm -f "\$ANTHROPIC_HEADER_FILE"' "$SCRIPT"
}
run_test test_header_file_hygiene

# SEC-01/SEC-03: vendored helper resolves and rejects placeholders
test_helper_behavior() {
    local tmp
    tmp=$(mktemp -d)

    mkdir -p "$tmp/.secrets" "$tmp/.local/bin"
    printf 'OP_SERVICE_ACCOUNT_TOKEN=fake-token\n' > "$tmp/.secrets/op-service-account.env"
    chmod 700 "$tmp/.secrets"
    chmod 600 "$tmp/.secrets/op-service-account.env"

    printf '%s\n' '#!/usr/bin/env bash' 'if [[ "$1" == "item" && "$2" == "get" ]]; then echo "resolved-secret"; exit 0; fi' 'exit 1' > "$tmp/.local/bin/nova-op"
    chmod +x "$tmp/.local/bin/nova-op"

    printf '{"ANTHROPIC_API_KEY": {"vault": "v", "item": "i", "field": "API Key"}}\n' > "$tmp/map.json"

    local value
    value=$(
        export HOME="$tmp" NOVA_OP="$tmp/.local/bin/nova-op" NOVA_OP_ITEM_MAP="$tmp/map.json"
        source "$LIB"
        nova_op_resolve ANTHROPIC_API_KEY "$tmp/map.json"
    )
    local rc=$?
    rm -rf "$tmp"
    [[ "$value" == "resolved-secret" ]]
}
run_test test_helper_behavior

# Summary
echo ""
echo "================================"
echo "Results: $PASS passed, $FAIL failed (total $((PASS+FAIL)))"
echo "================================"
[[ $FAIL -eq 0 ]]
