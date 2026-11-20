#!/bin/bash
# DO NOT EDIT — installed/managed by nova-workspace:scripts/lib/nova-op-env.sh
# Last synced: 2026-11-20
# Local changes will be overwritten by the owning repo's installer.
#
# Vendored copy of the nova-workspace helper. Loads environment variables from
# ~/.openclaw/scripts/nova-op-item-map.json and resolves each requested
# variable via nova-op by item ID. Vault IDs come from the map, not from any
# hardcoded per-script value.
#
# Usage:
#   source "$(dirname "$0")/lib/nova-op-env.sh"
#   nova_op_load_env ANTHROPIC_API_KEY
#
# Never prints secret values.

set -euo pipefail

NOVA_OP="${NOVA_OP:-$HOME/.local/bin/nova-op}"
NOVA_OP_ITEM_MAP="${NOVA_OP_ITEM_MAP:-$HOME/.openclaw/scripts/nova-op-item-map.json}"

nova_op_resolve() {
    local var="$1"
    local config_path="${2:-$NOVA_OP_ITEM_MAP}"

    local current
    eval "current=\${$var:-}"
    if [[ -n "$current" ]]; then
        echo "$current"
        return 0
    fi

    if [[ ! -f "$config_path" ]]; then
        echo "nova-op-env: item map not found: $config_path" >&2
        return 1
    fi

    local item field vault
    item=$(jq -r --arg k "$var" '.[$k].item // empty' "$config_path" 2>/dev/null)
    field=$(jq -r --arg k "$var" '.[$k].field // empty' "$config_path" 2>/dev/null)
    vault=$(jq -r --arg k "$var" '.[$k].vault // empty' "$config_path" 2>/dev/null)

    if [[ -z "$item" || -z "$field" || -z "$vault" ]]; then
        echo "nova-op-env: incomplete map entry for $var in $config_path" >&2
        return 1
    fi

    if [[ "$item" == "REPLACE_WITH_ITEM_ID" || "$vault" == "REPLACE_WITH_VAULT_ID" ]]; then
        echo "nova-op-env: $var still contains placeholder values in $config_path" >&2
        return 1
    fi

    local value
    value=$("$NOVA_OP" item get "$item" --vault "$vault" --field "$field" --reveal 2>&1) || {
        local rc=$?
        echo "nova-op-env: failed to resolve $var (item=$item field=$field vault=$vault, rc=$rc): $value" >&2
        return 1
    }

    if [[ -z "$value" ]]; then
        echo "nova-op-env: resolved empty value for $var (item=$item field=$field vault=$vault)" >&2
        return 1
    fi

    echo "$value"
}

nova_op_load_env() {
    local config_path="${NOVA_OP_ITEM_MAP:-$HOME/.openclaw/scripts/nova-op-item-map.json}"
    local had_error=0
    local var
    for var in "$@"; do
        local current
        eval "current=\${$var:-}"
        if [[ -n "$current" ]]; then
            continue
        fi
        local value
        if value=$(nova_op_resolve "$var" "$config_path"); then
            export "$var=$value"
        else
            had_error=1
        fi
    done
    return "$had_error"
}
