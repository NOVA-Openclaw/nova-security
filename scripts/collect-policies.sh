#!/bin/bash
# collect-policies.sh - Active security policy collector
# Runs on each message to detect and apply policy statements
#
# Usage: collect-policies.sh "message text"
#        echo "message text" | collect-policies.sh
#
# Environment:
#   SENDER_NAME    - Who sent the message
#   SENDER_ID      - Sender's identifier (phone, user_id, etc.)
#   SENDER_ENTITY  - Sender's entity_id (if known)
#   MESSAGE_ID     - Message identifier for audit

set -e

# Configuration
MIN_CONFIDENCE=0.9  # Auto-apply threshold
DB_NAME="${DB_NAME:-nova_memory}"
LOG_FILE="${LOG_FILE:-/home/nova/clawd/logs/policy-collector.log}"

# Input
INPUT_TEXT="${1:-$(cat)}"
[ -z "$INPUT_TEXT" ] && exit 0

# Sender info
SENDER="${SENDER_NAME:-unknown}"
SENDER_ENTITY="${SENDER_ENTITY:-}"
MESSAGE_ID="${MESSAGE_ID:-}"

# Pre-filter: Check if message might contain policy statements
# This saves API calls for non-policy messages
contains_policy_pattern() {
    local text="$1"
    local patterns=(
        "trust(ed)?\s+\w+"
        "don'?t\s+trust"
        "communicate\s+(freely\s+)?with"
        "don'?t\s+(share|tell)"
        "ignore\s+(messages?\s+from)?"
        "listen\s+to.+but\s+don'?t"
        "is\s+(an?\s+)?(admin|administrator|operator|trusted)"
        "(can|may|allowed\s+to)\s+\w+"
        "(cannot|can'?t|shouldn'?t|must\s+not)\s+\w+"
        "until\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|\d)"
        "role\s+as"
        "permission\s+to"
    )
    
    for pattern in "${patterns[@]}"; do
        if echo "$text" | grep -qiE "$pattern"; then
            return 0
        fi
    done
    return 1
}

# Quick exit if no policy patterns detected
if ! contains_policy_pattern "$INPUT_TEXT"; then
    exit 0
fi

# Log that we're processing
log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$LOG_FILE"
}

log "Policy pattern detected in message from $SENDER"

# Get API key
[ -z "$ANTHROPIC_API_KEY" ] && [ -f ~/.secrets/anthropic-api-key ] && \
    ANTHROPIC_API_KEY=$(cat ~/.secrets/anthropic-api-key)
[ -z "$ANTHROPIC_API_KEY" ] && { log "ERROR: No API key"; exit 1; }

# Get existing entities for resolution context
ENTITY_CONTEXT=$(psql -h localhost -U nova -d "$DB_NAME" -t -A -c "
    SELECT name FROM entities ORDER BY last_seen DESC NULLS LAST LIMIT 50;
" 2>/dev/null | tr '\n' ', ' | head -c 500)

ROLE_CONTEXT=$(psql -h localhost -U nova -d "$DB_NAME" -t -A -c "
    SELECT name FROM entity_roles ORDER BY name;
" 2>/dev/null | tr '\n' ', ')

# Build extraction prompt
PROMPT="You are a security policy extractor. Analyze this message for EXPLICIT security policy statements.

SENDER: ${SENDER}
MESSAGE: ${INPUT_TEXT}

KNOWN ENTITIES: ${ENTITY_CONTEXT:-none}
KNOWN ROLES: ${ROLE_CONTEXT:-user, operator, admin, agent, external_agent, service}

Extract ONLY explicit, unambiguous security policy statements. Do not infer policies.
Be conservative - only extract when the intent is clear.

Policy types:
- communication: Who can send/receive messages
- information_sharing: What info can be shared with whom
- action_permission: What actions an entity can request
- response_mode: How to handle messages (e.g., listen but don't respond)
- data_access: Access to specific data/resources
- delegation: Can delegate tasks to others

Actions: allow, deny, require_approval

Return JSON:
{
  \"policies\": [
    {
      \"policy_type\": \"string\",
      \"action\": \"allow|deny|require_approval\",
      \"subject_entity\": \"name or null\",
      \"subject_role\": \"role name or null\",
      \"target_entity\": \"name or null\",
      \"target_role\": \"role name or null\",
      \"resource_pattern\": \"pattern or null\",
      \"trust_level_change\": \"0-5 or null\",
      \"role_to_assign\": \"role name or null\",
      \"expires_at\": \"ISO date or null\",
      \"conditions\": {},
      \"confidence\": 0.0-1.0,
      \"original_text\": \"exact quote\"
    }
  ],
  \"no_policies\": true
}

If no clear policy statements found, return: {\"no_policies\": true}
Return ONLY valid JSON."

# Call API
PAYLOAD=$(jq -n --arg prompt "$PROMPT" '{
  model: "claude-sonnet-4-20250514",
  max_tokens: 1024,
  messages: [{role: "user", content: $prompt}]
}')

RESPONSE=$(curl -s https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d "$PAYLOAD" | jq -r '.content[0].text // empty')

[ -z "$RESPONSE" ] && { log "ERROR: Empty API response"; exit 1; }

# Check if any policies found
if echo "$RESPONSE" | jq -e '.no_policies == true' > /dev/null 2>&1; then
    log "No policies extracted"
    exit 0
fi

# Process extracted policies
echo "$RESPONSE" | jq -c '.policies[]?' 2>/dev/null | while read -r policy; do
    [ -z "$policy" ] && continue
    
    policy_type=$(echo "$policy" | jq -r '.policy_type')
    action=$(echo "$policy" | jq -r '.action')
    subject_entity=$(echo "$policy" | jq -r '.subject_entity // empty')
    subject_role=$(echo "$policy" | jq -r '.subject_role // empty')
    target_entity=$(echo "$policy" | jq -r '.target_entity // empty')
    resource_pattern=$(echo "$policy" | jq -r '.resource_pattern // empty')
    trust_level_change=$(echo "$policy" | jq -r '.trust_level_change // empty')
    role_to_assign=$(echo "$policy" | jq -r '.role_to_assign // empty')
    expires_at=$(echo "$policy" | jq -r '.expires_at // empty')
    confidence=$(echo "$policy" | jq -r '.confidence // 0.5')
    original_text=$(echo "$policy" | jq -r '.original_text // empty')
    
    log "Extracted: type=$policy_type action=$action subject=$subject_entity/$subject_role confidence=$confidence"
    
    # Resolve entity names to IDs
    entity_id=""
    if [ -n "$subject_entity" ]; then
        entity_id=$(psql -h localhost -U nova -d "$DB_NAME" -t -A -c "
            SELECT id FROM entities 
            WHERE name ILIKE '$(echo "$subject_entity" | sed "s/'/''/g")' 
               OR '$(echo "$subject_entity" | sed "s/'/''/g")' = ANY(nicknames)
            LIMIT 1;
        " 2>/dev/null)
    fi
    
    role_id=""
    if [ -n "$subject_role" ]; then
        role_id=$(psql -h localhost -U nova -d "$DB_NAME" -t -A -c "
            SELECT id FROM entity_roles WHERE name = '$(echo "$subject_role" | sed "s/'/''/g")';
        " 2>/dev/null)
    fi
    
    target_entity_id=""
    if [ -n "$target_entity" ]; then
        target_entity_id=$(psql -h localhost -U nova -d "$DB_NAME" -t -A -c "
            SELECT id FROM entities WHERE name ILIKE '$(echo "$target_entity" | sed "s/'/''/g")' LIMIT 1;
        " 2>/dev/null)
    fi
    
    # Handle trust level changes
    if [ -n "$trust_level_change" ] && [ -n "$entity_id" ]; then
        log "Updating trust level for entity $entity_id to $trust_level_change"
        
        # Check confidence threshold
        if (( $(echo "$confidence >= $MIN_CONFIDENCE" | bc -l) )); then
            psql -h localhost -U nova -d "$DB_NAME" -c "
                UPDATE entities SET trust_level = $trust_level_change WHERE id = $entity_id;
                INSERT INTO policy_audit (policy_id, action, new_values, source_message_id, notes)
                VALUES (NULL, 'trust_change', 
                    jsonb_build_object('entity_id', $entity_id, 'new_level', $trust_level_change, 'confidence', $confidence),
                    '$(echo "$MESSAGE_ID" | sed "s/'/''/g")',
                    'Auto-applied trust level change');
            " 2>/dev/null
            log "Applied trust level change (auto, confidence=$confidence)"
        else
            log "Queued trust level change for review (confidence=$confidence < $MIN_CONFIDENCE)"
            # TODO: Queue for review
        fi
    fi
    
    # Handle role assignments
    if [ -n "$role_to_assign" ] && [ -n "$entity_id" ]; then
        log "Assigning role $role_to_assign to entity $entity_id"
        
        if (( $(echo "$confidence >= $MIN_CONFIDENCE" | bc -l) )); then
            psql -h localhost -U nova -d "$DB_NAME" -c "
                SELECT assign_role($entity_id, '$(echo "$role_to_assign" | sed "s/'/''/g")', $SENDER_ENTITY, NULL, 'Auto-assigned via policy collector');
            " 2>/dev/null
            log "Applied role assignment (auto)"
        else
            log "Queued role assignment for review"
        fi
    fi
    
    # Create security policy record
    if [ -n "$entity_id" ] || [ -n "$role_id" ]; then
        log "Creating security policy record"
        
        # Build SQL
        expires_sql="NULL"
        [ -n "$expires_at" ] && expires_sql="'$expires_at'"
        
        target_entity_sql="NULL"
        [ -n "$target_entity_id" ] && target_entity_sql="$target_entity_id"
        
        resource_sql="NULL"
        [ -n "$resource_pattern" ] && resource_sql="'$(echo "$resource_pattern" | sed "s/'/''/g")'"
        
        entity_sql="NULL"
        [ -n "$entity_id" ] && entity_sql="$entity_id"
        
        role_sql="NULL"
        [ -n "$role_id" ] && role_sql="$role_id"
        
        if (( $(echo "$confidence >= $MIN_CONFIDENCE" | bc -l) )); then
            psql -h localhost -U nova -d "$DB_NAME" -c "
                SELECT create_policy(
                    $entity_sql,
                    $role_sql,
                    '$policy_type',
                    '$action',
                    $target_entity_sql,
                    $resource_sql,
                    100,
                    $expires_sql,
                    'extracted',
                    '$(echo "$MESSAGE_ID" | sed "s/'/''/g")',
                    '$(echo "$original_text" | sed "s/'/''/g")',
                    $confidence,
                    $SENDER_ENTITY
                );
            " 2>/dev/null
            log "Created policy (auto-applied)"
        else
            log "Policy queued for review (confidence=$confidence)"
            # Insert as disabled pending review
            psql -h localhost -U nova -d "$DB_NAME" -c "
                INSERT INTO security_policies (
                    entity_id, role_id, policy_type, action,
                    target_entity_id, resource_pattern,
                    expires_at, source, source_message_id, original_text,
                    confidence, enabled
                ) VALUES (
                    $entity_sql, $role_sql, '$policy_type', '$action',
                    $target_entity_sql, $resource_sql,
                    $expires_sql, 'extracted', '$(echo "$MESSAGE_ID" | sed "s/'/''/g")', 
                    '$(echo "$original_text" | sed "s/'/''/g")',
                    $confidence, FALSE
                );
            " 2>/dev/null
            log "Created policy (disabled, pending review)"
        fi
    else
        log "WARNING: Could not resolve entity/role for policy"
    fi
done

log "Policy collection complete"
