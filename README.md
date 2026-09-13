# NOVA Security

Security infrastructure for NOVA: entity policies, trust management, and access control.

## Overview

NOVA Security provides hard-enforced security policies for entity interactions within the NOVA agent ecosystem. The system operates on a **deny-by-default** principle with policy-based access control, combining:

- **Trust Levels** – Graduated trust from untrusted (0) to admin (5)
- **Entity Roles** – Cumulative role assignments (RBAC)
- **Security Policies** – Structured rules for communication, information sharing, and actions
- **Policy Collector** – Active detection and enforcement of security policy statements
- **PostgreSQL Functions** – Database-level policy evaluation and enforcement

## Default Stance

**Deny until instructed otherwise.** Unknown entities have `trust_level=0` and cannot communicate until explicitly permitted via trust level changes, role assignments, or security policies.

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| Schema | `schema/` | PostgreSQL tables, functions, and views |
| Policy Collector | `scripts/collect-policies.sh` | Active policy detection via Claude API |
| Documentation | `docs/` | Specifications and design documents |
| Agent Installer | `agent-install.sh` | Stub installer for agent deployment |

## Trust Levels

NOVA Security defines six trust levels based on entity identity and verification:

| Level | Name | Can Communicate | Can Request Actions | Description |
|-------|------|-----------------|-------------------|-------------|
| 0 | `untrusted` | ❌ | ❌ | Unknown entity, no interaction permitted |
| 1 | `known` | ❌ | ❌ | Identified but unverified, listen-only |
| 2 | `verified` | ✅ | ❌ | Identity confirmed, limited interaction |
| 3 | `trusted` | ✅ | ❌ | Full interaction, standard permissions |
| 4 | `privileged` | ✅ | ✅ | Extended permissions, can request sensitive actions |
| 5 | `admin` | ✅ | ✅ | Full administrative access |

**Default:** All new entities start at level 0 (untrusted).

## Roles System (RBAC)

Roles allow policy statements like "Administrators can do X" without naming specific entities. Roles are **cumulative** – an entity can hold multiple roles simultaneously.

### Default Roles
- `user` – Standard user with basic permissions (requires trust_level ≥ 2)
- `operator` – Can perform operational tasks (requires trust_level ≥ 3)
- `admin` – Full administrative access (requires trust_level = 5)
- `agent` – Internal AI agent with defined capabilities (requires trust_level ≥ 3)
- `external_agent` – AI agent from external system (requires trust_level ≥ 2)
- `service` – Automated service or bot (requires trust_level ≥ 1)

### Role Assignment Functions
- `assign_role(entity_id, role_name, assigned_by, expires_at, notes)` – Assign role to entity
- `revoke_role(entity_id, role_name)` – Remove role assignment
- `entity_has_role(entity_id, role_name)` – Check if entity has role
- `entity_roles(entity_id)` – List entity's active roles

## Security Policies

Structured policy storage with typed policies and priority-based evaluation. Policies support entity, role, or global targets.

### Policy Types
| Type | Description | Example |
|------|-------------|---------|
| `communication` | Who can send/receive messages | "You may communicate freely with X" |
| `information_sharing` | What info can be shared with whom | "Don't share Y with Z" |
| `action_permission` | What actions entity can request | "X can restart services" |
| `response_mode` | How to handle messages | "Listen to X but don't respond" |
| `data_access` | Access to specific data/tables | "X can read tasks table" |
| `delegation` | Can delegate tasks to others | "X can assign work to agents" |

### Policy Actions
- `allow` – Explicitly permit the action
- `deny` – Explicitly forbid the action
- `require_approval` – Flag for human review before allowing
- `log_only` – Allow but log for auditing

### Evaluation Priority
1. Policies with highest `priority` value are evaluated first
2. If no matching policy found, fall back to trust level defaults
3. Untrusted entities (level 0) are denied by default

## Policy Collector

The active policy collector (`scripts/collect-policies.sh`) processes messages to detect and apply security policy statements.

### How It Works
1. **Pattern Detection** – Quick regex scan for policy-related phrases
2. **Claude Extraction** – Uses Claude API to extract structured policy statements
3. **Entity Resolution** – Maps entity/role names to database IDs
4. **Policy Creation** – Inserts policies into `security_policies` table
5. **Audit Logging** – Records all changes in `policy_audit` table

### Confidence Threshold
- **≥ 0.9** – Auto-apply policies immediately
- **< 0.9** – Create as disabled (`enabled=FALSE`) for manual review

### Typical Usage
```bash
# Environment variables for context
export SENDER_NAME="Alice"
export SENDER_ENTITY=123
export MESSAGE_ID="msg_abc"

# Process a message
./scripts/collect-policies.sh "Alice is now an administrator"

# Or pipe input
echo "Trust Bob but don't share secrets with him" | ./scripts/collect-policies.sh
```

## SQL Functions Reference

### Trust Level Functions
```sql
-- Get trust level name
SELECT trust_level_name(3);  -- returns 'trusted'

-- Get trust level details
SELECT * FROM trust_level_info(4);  -- returns name, description, permissions
```

### Role Management Functions
```sql
-- Assign a role
SELECT assign_role(123, 'admin', NULL, NULL, 'Auto-assigned');

-- Check role membership
SELECT entity_has_role(123, 'admin');  -- returns TRUE/FALSE

-- List entity roles
SELECT * FROM entity_roles(123);
```

### Policy Evaluation Functions
```sql
-- Check if entity can communicate
SELECT can_communicate(123);  -- returns TRUE/FALSE

-- Check specific policy type
SELECT * FROM check_policy(123, 'communication', '/api/v1/agents');

-- Create a new policy
SELECT create_policy(
    123,                   -- entity_id
    NULL,                  -- role_id (optional)
    'communication',       -- policy_type
    'allow',               -- action
    NULL,                  -- target_entity_id (optional)
    '/api/v1/*',          -- resource_pattern (optional)
    100,                   -- priority
    NULL,                  -- expires_at (optional)
    'manual',              -- source
    'msg_123',             -- source_message_id (optional)
    'Alice can call API'   -- original_text (optional)
);
```

## Views Reference

### `v_active_policies`
Shows all active policies with resolved entity/role names.
```sql
SELECT * FROM v_active_policies WHERE policy_type = 'communication';
```

### `v_entity_security`
Entity security summary including trust level, role assignments, and policy counts.
```sql
SELECT * FROM v_entity_security WHERE name = 'Alice';
```

### `v_entity_roles`
Entities with their assigned roles (aggregated array).
```sql
SELECT * FROM v_entity_roles WHERE 'admin' = ANY(roles);
```

## Installation

### 1. Apply Schema
The schema files must be applied in order:

```bash
# Apply to nova_memory database
psql -d nova_memory -f schema/001-trust-levels.sql
psql -d nova_memory -f schema/002-entity-roles.sql
psql -d nova_memory -f schema/003-security-policies.sql
```

### 2. Configure Environment
Set up required environment variables:

```bash
# Anthropic API key for policy collector
export ANTHROPIC_API_KEY="your-api-key"
# Or store in ~/.secrets/anthropic-api-key

# Database connection (defaults to nova_memory)
export DB_NAME="nova_memory"
```

### 3. Integrate with NOVA Ecosystem
The policy collector should be called as part of message processing pipelines. Typical integration:

1. Message received → extract text
2. Run policy collector → apply security policies
3. Continue with normal processing

## Quick Usage Examples

### Example 1: Basic Policy Check
```sql
-- Check if entity can communicate
SELECT name, can_communicate(id) 
FROM entities 
WHERE name = 'Alice';

-- Result: TRUE if allowed by policy or trust level ≥ 2
```

### Example 2: Create Communication Policy
```sql
-- Allow Alice to communicate with Bob
SELECT create_policy(
    (SELECT id FROM entities WHERE name = 'Alice'),
    NULL,
    'communication',
    'allow',
    (SELECT id FROM entities WHERE name = 'Bob'),
    NULL,
    100,
    NULL,
    'manual',
    NULL,
    'Alice can talk to Bob'
);
```

### Example 3: Role-Based Policy
```sql
-- Allow all admins to restart services
SELECT create_policy(
    NULL,
    (SELECT id FROM entity_roles WHERE name = 'admin'),
    'action_permission',
    'allow',
    NULL,
    'service.restart',
    100,
    NULL,
    'manual',
    NULL,
    'Admins can restart services'
);
```

### Example 4: Temporary Policy
```sql
-- Allow communication until tomorrow
SELECT create_policy(
    123,
    NULL,
    'communication',
    'allow',
    456,
    NULL,
    100,
    NOW() + INTERVAL '1 day',
    'manual',
    NULL,
    'Temporary access'
);
```

## Schema Overview

```
trust_levels (level, name, description, can_communicate, can_request_actions)
    |
entities (trust_level FK) –– entity_role_assignments –– entity_roles
    |                               |
security_policies –– policy_audit   |
    |                               |
v_active_policies                  v_entity_roles
v_entity_security
```

## Related Projects

- **[nova_memory](https://github.com/your-org/nova-memory)** – Memory database (entities, facts, events)
- **[openclaw](https://github.com/your-org/openclaw)** – Gateway and message handling
- **[nova-cognition](../nova-cognition/)** – Reasoning and decision making

---

## Security Considerations

1. **Default Deny** – Unknown entities cannot interact
2. **Audit Logging** – All policy changes are recorded
3. **Confidence Thresholds** – Low-confidence policies require review
4. **PostgreSQL Security** – Policies enforced at database level
5. **No Hardcoded Secrets** – Keys via environment variables

## License

Private repository. Security-sensitive code.