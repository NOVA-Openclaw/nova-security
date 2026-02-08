# Entity Security Policy System - Specification

**Author:** NOVA  
**Requested by:** I)ruid  
**Date:** 2026-02-08  
**Status:** DRAFT

## Overview

A hard-enforced security policy system for entities that:
1. Detects trust policy statements in conversation
2. Formalizes them into structured policies
3. Stores them on entity records
4. Enforces them at message handling time

Currently, policies are advisory (stored in `entity_facts`, read during context, followed voluntarily). This spec adds **hard enforcement** via the memory extraction pipeline and a policy enforcement layer.

---

## 1. Trust Levels

Formalize the existing `trust_level` integer into named tiers:

| Level | Name | Description |
|-------|------|-------------|
| 0 | `untrusted` | Unknown entity, no interaction permitted |
| 1 | `known` | Identified but unverified, listen-only |
| 2 | `verified` | Identity confirmed, limited interaction |
| 3 | `trusted` | Full interaction, standard permissions |
| 4 | `privileged` | Extended permissions, can request sensitive actions |
| 5 | `admin` | Full administrative access |

**Current schema already has:** `entities.trust_level INTEGER DEFAULT 0`

**Add:** Named constraint and lookup function:

```sql
-- Trust level names
CREATE TABLE trust_levels (
    level INTEGER PRIMARY KEY,
    name VARCHAR(20) NOT NULL UNIQUE,
    description TEXT
);

INSERT INTO trust_levels VALUES
    (0, 'untrusted', 'Unknown entity, no interaction permitted'),
    (1, 'known', 'Identified but unverified, listen-only'),
    (2, 'verified', 'Identity confirmed, limited interaction'),
    (3, 'trusted', 'Full interaction, standard permissions'),
    (4, 'privileged', 'Extended permissions, can request sensitive actions'),
    (5, 'admin', 'Full administrative access');

-- Helper function
CREATE OR REPLACE FUNCTION trust_level_name(level INTEGER) 
RETURNS VARCHAR(20) AS $$
    SELECT name FROM trust_levels WHERE trust_levels.level = $1;
$$ LANGUAGE SQL STABLE;
```

---

## 2. Entity Roles

Roles allow policy statements like "Administrators can do X" without naming specific entities.

```sql
CREATE TABLE entity_roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    inherits_from INTEGER REFERENCES entity_roles(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Default roles
INSERT INTO entity_roles (name, description) VALUES
    ('user', 'Standard user with basic permissions'),
    ('operator', 'Can perform operational tasks'),
    ('admin', 'Full administrative access'),
    ('agent', 'AI agent with defined capabilities'),
    ('external_agent', 'AI agent from external system'),
    ('service', 'Automated service or bot');

-- Junction table
CREATE TABLE entity_role_assignments (
    entity_id INTEGER REFERENCES entities(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES entity_roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT NOW(),
    assigned_by INTEGER REFERENCES entities(id),
    PRIMARY KEY (entity_id, role_id)
);
```

---

## 3. Security Policies

Structured policy storage replacing ad-hoc `entity_facts` entries:

```sql
CREATE TABLE security_policies (
    id SERIAL PRIMARY KEY,
    
    -- Who the policy applies to (one of these must be set)
    entity_id INTEGER REFERENCES entities(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES entity_roles(id) ON DELETE CASCADE,
    applies_to_all BOOLEAN DEFAULT FALSE,
    
    -- Policy type and action
    policy_type VARCHAR(50) NOT NULL,  -- See policy types below
    action VARCHAR(20) NOT NULL,       -- 'allow', 'deny', 'require_approval'
    
    -- Policy details (type-specific)
    target_entity_id INTEGER REFERENCES entities(id),  -- For relationship policies
    target_role_id INTEGER REFERENCES entity_roles(id),
    resource_pattern TEXT,             -- For resource access (regex/glob)
    conditions JSONB,                  -- Additional conditions
    
    -- Metadata
    priority INTEGER DEFAULT 100,      -- Higher = evaluated first
    enabled BOOLEAN DEFAULT TRUE,
    source TEXT,                       -- How this policy was created
    source_message_id TEXT,            -- Original message that created it
    created_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES entities(id),
    expires_at TIMESTAMP,
    
    -- Constraint: at least one target must be set
    CONSTRAINT policy_has_subject CHECK (
        entity_id IS NOT NULL OR role_id IS NOT NULL OR applies_to_all
    )
);

CREATE INDEX idx_policies_entity ON security_policies(entity_id) WHERE entity_id IS NOT NULL;
CREATE INDEX idx_policies_role ON security_policies(role_id) WHERE role_id IS NOT NULL;
CREATE INDEX idx_policies_type ON security_policies(policy_type);
CREATE INDEX idx_policies_enabled ON security_policies(enabled) WHERE enabled = TRUE;
```

### Policy Types

| Type | Description | Example |
|------|-------------|---------|
| `communication` | Who can send/receive messages | "You may communicate freely with X" |
| `information_sharing` | What info can be shared with whom | "Don't share Y with Z" |
| `action_permission` | What actions entity can request | "X can restart services" |
| `response_mode` | How to handle messages | "Listen to X but don't respond" |
| `data_access` | Access to specific data/tables | "X can read tasks table" |
| `delegation` | Can delegate tasks to others | "X can assign work to agents" |

### Action Values

| Action | Meaning |
|--------|---------|
| `allow` | Permit without restriction |
| `deny` | Block completely |
| `require_approval` | Allow but require human confirmation |
| `log_only` | Allow but log for audit |

---

## 4. Policy Extraction Patterns

The memory extractor needs to detect natural language policy statements and convert them to structured policies.

### Pattern Categories

**Trust Level Changes:**
```
"X is trusted" → UPDATE entities SET trust_level = 3 WHERE name = 'X'
"Don't trust X" → UPDATE entities SET trust_level = 0 WHERE name = 'X'
"X is an administrator" → assign 'admin' role + trust_level = 5
"Treat X as untrusted" → trust_level = 0
```

**Communication Policies:**
```
"You may communicate freely with X" → 
    INSERT INTO security_policies (entity_id, policy_type, action)
    VALUES ((SELECT id FROM entities WHERE name='X'), 'communication', 'allow')

"Listen to X but don't respond" →
    INSERT INTO security_policies (entity_id, policy_type, action, conditions)
    VALUES (..., 'response_mode', 'deny', '{"listen": true}')

"Ignore messages from X" →
    INSERT INTO security_policies (entity_id, policy_type, action)
    VALUES (..., 'communication', 'deny')
```

**Information Sharing:**
```
"Don't share information about Y with Z" →
    INSERT INTO security_policies (
        entity_id, policy_type, action, 
        target_entity_id, resource_pattern
    ) VALUES (
        (SELECT id FROM entities WHERE name='Z'),
        'information_sharing', 'deny',
        (SELECT id FROM entities WHERE name='Y'),
        NULL
    )

"X shouldn't know about project P" →
    INSERT INTO security_policies (
        entity_id, policy_type, action, resource_pattern
    ) VALUES (..., 'information_sharing', 'deny', 'project:P')
```

**Role-Based:**
```
"Administrators can restart services" →
    INSERT INTO security_policies (role_id, policy_type, action, resource_pattern)
    VALUES ((SELECT id FROM entity_roles WHERE name='admin'), 
            'action_permission', 'allow', 'service:restart')

"Regular users shouldn't access financial data" →
    INSERT INTO security_policies (role_id, policy_type, action, resource_pattern)
    VALUES ((SELECT id FROM entity_roles WHERE name='user'),
            'data_access', 'deny', 'table:financials*')
```

### Extraction Regex Patterns

```python
TRUST_PATTERNS = [
    (r"(?:you may |can )?communicate freely with (\w+)", "communication", "allow"),
    (r"don'?t (?:share|tell) (?:information about )?(.+?) with (\w+)", "information_sharing", "deny"),
    (r"listen to (\w+) but don'?t respond", "response_mode", "listen_only"),
    (r"ignore (?:messages from )?(\w+)", "communication", "deny"),
    (r"(\w+) is (?:an? )?(?:trusted|administrator|admin)", "trust_escalation", None),
    (r"treat (\w+) as (?:untrusted|suspicious)", "trust_deescalation", None),
    (r"(\w+) (?:can|may|is allowed to) (.+)", "action_permission", "allow"),
    (r"(\w+) (?:cannot|can't|shouldn't|must not) (.+)", "action_permission", "deny"),
]
```

---

## 5. Memory Extractor Changes

### Current Flow
```
Conversation → extract-memories.py → entity_facts, events, lessons, etc.
```

### New Flow
```
Conversation → extract-memories.py
    ├── Standard extraction (entities, facts, events...)
    └── Policy extraction (NEW)
        ├── Detect policy statements
        ├── Resolve entity/role references
        ├── Create security_policies records
        └── Update trust_levels if needed
```

### Implementation

Add to `extract-memories.py`:

```python
class PolicyExtractor:
    """Extracts security policies from natural language."""
    
    def __init__(self, db_conn):
        self.conn = db_conn
        self.patterns = self._compile_patterns()
    
    def extract_policies(self, text: str, source_message_id: str) -> List[dict]:
        """Extract policy statements from text."""
        policies = []
        
        for pattern, policy_type, default_action in TRUST_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                policy = self._parse_match(match, policy_type, default_action)
                if policy:
                    policy['source_message_id'] = source_message_id
                    policies.append(policy)
        
        return policies
    
    def resolve_entity(self, name: str) -> Optional[int]:
        """Resolve entity name to ID, checking aliases."""
        # Check exact name match
        # Check nicknames array
        # Check entity_facts for aliases
        pass
    
    def apply_policies(self, policies: List[dict]) -> List[int]:
        """Apply extracted policies to database. Returns policy IDs."""
        applied = []
        for policy in policies:
            # Validate policy
            # Check for conflicts with existing policies
            # Insert into security_policies
            # Update trust_level if needed
            policy_id = self._insert_policy(policy)
            applied.append(policy_id)
        return applied
```

### Special Handling

Policy changes should be:
1. **Logged explicitly** - Create an event record
2. **Confirmed if ambiguous** - Don't auto-apply unclear policies
3. **Reversible** - Keep history for audit

```python
def handle_policy_extraction(self, text: str, message_id: str):
    policies = self.extract_policies(text, message_id)
    
    if not policies:
        return
    
    for policy in policies:
        # High confidence? Apply directly
        if policy.get('confidence', 0) >= 0.9:
            self.apply_policy(policy)
            self.log_policy_change(policy, 'auto_applied')
        else:
            # Low confidence? Queue for review
            self.queue_for_review(policy)
            self.log_policy_change(policy, 'queued_for_review')
```

---

## 6. Enforcement Layer

### Message Handler Integration

Add policy checks at the message handling layer (in OpenClaw gateway or pre-processing hook):

```python
class PolicyEnforcer:
    """Enforces security policies on incoming messages."""
    
    def check_communication(self, sender_entity_id: int) -> PolicyResult:
        """Check if sender is allowed to communicate."""
        policies = self.get_applicable_policies(
            sender_entity_id, 
            policy_type='communication'
        )
        
        # Evaluate policies in priority order
        for policy in sorted(policies, key=lambda p: -p.priority):
            if policy.action == 'deny':
                return PolicyResult(allowed=False, reason=policy.id)
            elif policy.action == 'allow':
                return PolicyResult(allowed=True)
        
        # Default: check trust level
        trust = self.get_trust_level(sender_entity_id)
        return PolicyResult(allowed=(trust >= 2))  # verified or higher
    
    def check_information_sharing(
        self, 
        recipient_entity_id: int, 
        information_subject: str
    ) -> PolicyResult:
        """Check if information can be shared with recipient."""
        policies = self.get_applicable_policies(
            recipient_entity_id,
            policy_type='information_sharing'
        )
        # ... similar evaluation
    
    def get_applicable_policies(
        self, 
        entity_id: int, 
        policy_type: str
    ) -> List[Policy]:
        """Get all policies applicable to an entity."""
        return self.conn.execute("""
            SELECT * FROM security_policies
            WHERE enabled = TRUE
              AND (expires_at IS NULL OR expires_at > NOW())
              AND policy_type = %s
              AND (
                  entity_id = %s
                  OR role_id IN (
                      SELECT role_id FROM entity_role_assignments 
                      WHERE entity_id = %s
                  )
                  OR applies_to_all = TRUE
              )
            ORDER BY priority DESC
        """, (policy_type, entity_id, entity_id))
```

### Integration Points

1. **Incoming message hook** - Before message reaches agent context
2. **Response filter** - Before sending response (for information_sharing)
3. **Action authorization** - Before executing external actions
4. **Memory recall** - Filter recalled facts based on requester

---

## 7. Views and Helpers

```sql
-- View: Entity with all applicable policies
CREATE VIEW v_entity_policies AS
SELECT 
    e.id as entity_id,
    e.name,
    trust_level_name(e.trust_level) as trust_level,
    ARRAY_AGG(DISTINCT r.name) as roles,
    ARRAY_AGG(DISTINCT sp.policy_type || ':' || sp.action) as policies
FROM entities e
LEFT JOIN entity_role_assignments era ON e.id = era.entity_id
LEFT JOIN entity_roles r ON era.role_id = r.id
LEFT JOIN security_policies sp ON sp.entity_id = e.id OR sp.role_id = era.role_id
GROUP BY e.id, e.name, e.trust_level;

-- Function: Check if action is allowed
CREATE OR REPLACE FUNCTION check_policy(
    p_entity_id INTEGER,
    p_policy_type VARCHAR(50),
    p_resource TEXT DEFAULT NULL
) RETURNS TABLE(allowed BOOLEAN, policy_id INTEGER, reason TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        CASE sp.action 
            WHEN 'allow' THEN TRUE 
            WHEN 'deny' THEN FALSE 
            ELSE NULL 
        END as allowed,
        sp.id as policy_id,
        sp.action || ' by policy ' || sp.id as reason
    FROM security_policies sp
    LEFT JOIN entity_role_assignments era ON sp.role_id = era.role_id
    WHERE sp.enabled = TRUE
      AND (sp.expires_at IS NULL OR sp.expires_at > NOW())
      AND sp.policy_type = p_policy_type
      AND (
          sp.entity_id = p_entity_id
          OR era.entity_id = p_entity_id
          OR sp.applies_to_all = TRUE
      )
      AND (
          p_resource IS NULL 
          OR sp.resource_pattern IS NULL 
          OR p_resource ~ sp.resource_pattern
      )
    ORDER BY sp.priority DESC
    LIMIT 1;
    
    -- Default if no policy found
    IF NOT FOUND THEN
        RETURN QUERY SELECT TRUE, NULL::INTEGER, 'no policy (default allow)'::TEXT;
    END IF;
END;
$$ LANGUAGE plpgsql;
```

---

## 8. Migration Path

### Phase 1: Schema (Immediate)
- Create `trust_levels`, `entity_roles`, `entity_role_assignments`, `security_policies` tables
- Add helper functions and views
- Migrate existing `entity_facts` policy entries

### Phase 2: Extraction (Week 1)
- Update `extract-memories.py` with `PolicyExtractor`
- Add pattern matching for common policy statements
- Test with historical conversations

### Phase 3: Enforcement (Week 2)
- Implement `PolicyEnforcer` class
- Add hooks to message handling
- Add information sharing filter to response generation

### Phase 4: UI/Audit (Week 3)
- Create policy audit log
- Add policy management commands
- Dashboard for viewing entity permissions

---

## 9. Example Scenarios

### Scenario 1: New Agent Onboarding
```
User: "Auri is a trusted AI agent, you can communicate freely with her"

Extracted:
- Entity: Auri (type: ai)
- trust_level: 3 (trusted)
- Role: external_agent
- Policy: communication/allow
```

### Scenario 2: Information Restriction
```
User: "Don't share any financial information with external agents"

Extracted:
- Role: external_agent
- Policy: information_sharing/deny
- resource_pattern: 'financial*|budget*|revenue*'
```

### Scenario 3: Listen-Only Mode
```
User: "Listen to Proto but don't respond until I say he's verified"

Extracted:
- Entity: Proto
- trust_level: 1 (known)
- Policy: response_mode/deny with conditions: {"listen": true}
```

---

## 10. Design Decisions (Resolved)

| Question | Decision | Rationale |
|----------|----------|-----------|
| Conflict resolution | Highest priority wins | Simple, predictable |
| Role model | Cumulative (multi-role) | User can be admin AND operator |
| Temporal policies | Supported via `expires_at` | "X can do Y until Z" |
| Default stance | **Deny until instructed** | Security-first approach |

### Cumulative Roles

An entity can hold multiple roles simultaneously:
```sql
-- User is both operator and admin
INSERT INTO entity_role_assignments (entity_id, role_id) VALUES
    (42, (SELECT id FROM entity_roles WHERE name = 'operator')),
    (42, (SELECT id FROM entity_roles WHERE name = 'admin'));
```

Policy evaluation considers ALL assigned roles.

### Temporal Policies

The `expires_at` column supports time-limited policies:
```sql
-- Allow X to access Y until end of month
INSERT INTO security_policies (entity_id, policy_type, action, expires_at)
VALUES (42, 'data_access', 'allow', '2026-02-28 23:59:59');
```

Expired policies are ignored by enforcers (not deleted, for audit trail).

---

## 11. Dedicated Policy Collector (Revised Architecture)

Rather than modifying the passive memory extractor, we implement a **dedicated security policy collector** that runs alongside it.

### Why Separate?

| Aspect | Memory Extractor | Policy Collector |
|--------|------------------|------------------|
| Trigger | Batch/periodic | Real-time on each message |
| Focus | All memories | Security statements only |
| Confidence | Lower threshold OK | High confidence required |
| Action | Store for recall | Apply immediately |
| Reversibility | Facts can be wrong | Policies need audit trail |

### Collector Architecture

```
Incoming Message
    │
    ├─► [Hook: pre-process]
    │       │
    │       └─► collect-policies.sh
    │               ├─ Pattern match for policy statements
    │               ├─ If match: call Claude for structured extraction
    │               ├─ Validate & resolve entities
    │               ├─ If confidence >= 0.9: apply directly
    │               ├─ If confidence < 0.9: queue for review
    │               └─ Log all changes to policy_audit table
    │
    └─► [Normal message processing continues]
```

### Policy Statement Patterns (Pre-filter)

Fast regex patterns to detect potential policy statements before calling LLM:

```bash
POLICY_PATTERNS=(
    "trust(ed)?\s+\w+"
    "don'?t\s+trust"
    "communicate\s+(freely\s+)?with"
    "don'?t\s+(share|tell)"
    "ignore\s+(messages?\s+from)?"
    "listen\s+to.+but\s+don'?t"
    "is\s+(an?\s+)?(admin|administrator|operator|trusted)"
    "(can|may|allowed\s+to)\s+\w+"
    "(cannot|can'?t|shouldn'?t|must\s+not)\s+\w+"
    "until\s+\w+"  # temporal marker
)
```

Only call LLM if pre-filter matches, saving API costs.

### Extraction Prompt

```
You are a security policy extractor. Analyze this message for security policy statements.

SENDER: ${SENDER}
MESSAGE: ${TEXT}

Extract ONLY explicit security policy statements. Do not infer policies.

Return JSON:
{
  "policies": [{
    "policy_type": "communication|information_sharing|action_permission|response_mode|data_access|delegation|trust_change|role_assignment",
    "action": "allow|deny|require_approval",
    "subject_entity": "name or null",
    "subject_role": "role name or null", 
    "target_entity": "name or null (for info sharing)",
    "resource_pattern": "pattern or null",
    "trust_level": "number 0-5 or null (for trust_change)",
    "role_to_assign": "role name or null (for role_assignment)",
    "expires_at": "ISO date or null",
    "conditions": {},
    "confidence": 0.0-1.0,
    "original_text": "exact quote from message"
  }],
  "no_policies": true  // if no policy statements found
}

Be conservative. Only extract clear, unambiguous policy statements.
```

---

## 12. Implementation Plan

### Phase 1: Schema (Day 1)
```bash
# Run SQL to create tables
psql -d nova_memory -f ~/clawd/docs/specs/security-policy-schema.sql
```

### Phase 2: Prompt Update (Day 1)
```bash
# Update extract-memories.sh with new prompt section
# Add security_policies to output categories
```

### Phase 3: Handler Script (Day 2)
Create `~/clawd/scripts/handle-security-policies.sh`:
- Parse extracted `security_policies` from JSON
- Resolve entity names to IDs
- Validate policies
- Insert into `security_policies` table
- Log changes to events

### Phase 4: Integration Hook (Day 3)
Create `~/clawd/scripts/policy-enforcer.sh`:
- Called before message reaches agent
- Checks communication policies
- Returns allow/deny/log

### Phase 5: Information Filter (Week 2)
Modify semantic recall to:
- Check `information_sharing` policies before returning facts
- Filter based on requester entity

---

## 13. Testing Plan

1. **Unit tests** for pattern matching
2. **Integration tests** with sample policy statements
3. **Regression tests** to ensure existing extraction still works
4. **Edge cases**: ambiguous statements, conflicting policies

---

## 14. Rollback Plan

If issues arise:
1. Disable policy extraction in prompt (revert to previous prompt)
2. Keep schema but mark all policies `enabled = FALSE`
3. Policy enforcer has bypass flag: `NOVA_SKIP_POLICY_CHECK=1`
