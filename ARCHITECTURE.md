# NOVA Security Architecture

## System Overview

NOVA Security is a hard-enforced security policy system for the NOVA agent ecosystem. It provides entity trust management, role-based access control (RBAC), and policy-based authorization for agent interactions. The system combines PostgreSQL schema enforcement with AI-powered policy extraction from natural language.

### Core Components
1. **Trust Level System** – Six-tier trust hierarchy (0=untrusted to 5=admin)
2. **Role-Based Access Control** – Cumulative role assignments with minimum trust requirements
3. **Security Policy Engine** – Typed policies with priority-based evaluation
4. **Policy Collector** – Active detection and enforcement of security statements
5. **Audit System** – Comprehensive logging of all policy changes

## Design Philosophy

### 1. Deny by Default
- Unknown entities start at trust level 0 (untrusted)
- No implicit permissions – everything must be explicitly allowed
- Fallback to trust level defaults when no policy matches

### 2. Cumulative Permissions
- Entities can hold multiple roles simultaneously
- Permissions from all roles accumulate (OR logic)
- Higher trust levels inherit lower-level permissions

### 3. Priority-Based Evaluation
- Policies evaluated by priority (highest first)
- Explicit policies override trust level defaults
- Temporal policies allow time-limited access

### 4. Auditability
- Every policy change logged with source and timestamp
- Original message text preserved for context
- Confidence scores track extraction certainty

## Data Flow

### Message Processing Pipeline
```
Incoming Message
    │
    ├─► Policy Collector (Active)
    │       ├─ Pattern Detection (regex filters)
    │       ├─ Claude API Extraction (structured JSON)
    │       ├─ Entity/Role Resolution (name → ID mapping)
    │       ├─ Confidence Evaluation (≥0.9 auto-apply)
    │       └─ Policy Creation/Audit
    │
    ├─► Policy Evaluation (On-Demand)
    │       ├─ Security Hook (check_policy() calls)
    │       ├─ Priority-Based Matching
    │       └─ Default Trust Level Fallback
    │
    └─► Enforcement
            ├─ Communication Blocking (can_communicate())
            ├─ Information Filtering (check_policy())
            └─ Action Authorization (check_policy())
```

### Policy Collector Detailed Flow
1. **Input**: Message text, sender context, message ID
2. **Pre-filter**: Quick regex scan for policy-related phrases
3. **API Call**: Send to Claude with entity/role context for structured extraction
4. **Response Processing**: Parse JSON, validate policy types/actions
5. **Entity Resolution**: Map entity/role names to database IDs
6. **Confidence Check**: Compare against `MIN_CONFIDENCE` (0.9)
7. **Policy Application**:
   - High confidence: Create enabled policies, apply trust/role changes
   - Low confidence: Create disabled policies for review
8. **Audit Logging**: Record all changes in `policy_audit` table

## Schema Relationships

### Entity-Centric Security Model
```
trust_levels (reference table)
    ↑
entities (core entity registry)
    ├── entity_role_assignments (junction table)
    │       └── entity_roles (role definitions)
    │
    └── security_policies (active policies)
            └── policy_audit (change history)
```

### Table Descriptions

#### `trust_levels`
Reference table defining six trust levels with permissions. Each level specifies:
- `can_communicate`: Whether entities at this level can send/receive messages
- `can_request_actions`: Whether entities can request sensitive operations

#### `entities`
Core entity registry with `trust_level` foreign key reference. New entities default to level 0.

#### `entity_roles`
Role definitions with `min_trust_level` requirement. Default roles: user, operator, admin, agent, external_agent, service.

#### `entity_role_assignments`
Junction table linking entities to roles with optional expiration timestamp.

#### `security_policies`
Active policy rules with:
- Subject: `entity_id`, `role_id`, or `applies_to_all`
- Type: `communication`, `information_sharing`, `action_permission`, etc.
- Action: `allow`, `deny`, `require_approval`, `log_only`
- Targets: `target_entity_id`, `target_role_id`, `resource_pattern`
- Metadata: `priority`, `confidence`, `source`, `original_text`, `expires_at`

#### `policy_audit`
Immutable audit log tracking all policy changes.

## Policy Evaluation Logic

### Evaluation Algorithm
```pseudocode
function evaluate_policy(entity_id, policy_type, resource):
    # 1. Get entity's roles (active, non-expired)
    roles = get_entity_roles(entity_id)
    
    # 2. Find matching policies (highest priority first)
    policies = find_policies(entity_id, roles, policy_type, resource)
    sort_by_priority_desc(policies)
    
    # 3. Return first matching policy
    for policy in policies:
        if policy.matches(resource):
            return policy.action
    
    # 4. Fallback to trust level defaults
    trust_level = get_entity_trust_level(entity_id)
    return trust_level_defaults[trust_level]
```

### Policy Matching Precedence
1. Entity-specific policies (`entity_id = X`)
2. Role-based policies (`role_id = Y` where entity has role Y)
3. Global policies (`applies_to_all = TRUE`)
4. Trust level defaults

### Resource Pattern Matching
- `resource_pattern` supports PostgreSQL regex (`~` operator)
- Null pattern matches any resource
- Resource names are system-defined (e.g., `service.restart`, `/api/v1/agents`)

## Confidence-Based Auto-Apply

### Threshold Configuration
- `MIN_CONFIDENCE = 0.9` (configurable in script)
- Based on Claude extraction confidence score (0.0-1.0)

### High Confidence (≥ 0.9)
- Policies created with `enabled = TRUE`
- Trust level changes applied immediately
- Role assignments executed
- Assumption: Clear, unambiguous policy statements

### Low Confidence (< 0.9)
- Policies created with `enabled = FALSE`
- Queued for human review
- Trust/role changes deferred
- Prevents incorrect policy application from ambiguous statements

### Review Workflow
1. Low-confidence policies visible in `security_policies` (enabled=FALSE)
2. Human reviewer evaluates original text and confidence
3. Reviewer enables policy or marks for deletion
4. Audit trail preserves review decision

## Integration Points

### 1. Message Handling Systems
- **OpenClaw Gateway**: Call policy collector on incoming messages
- **Memory Pipeline**: Integrate with memory extraction for passive policy detection
- **Agent Chat**: Check `can_communicate()` before message delivery

### 2. Database Integration
- **nova_memory**: Primary database for all security tables
- **Row-Level Security**: Future extension using PostgreSQL RLS
- **Foreign Data Wrappers**: Potential integration with external identity systems

### 3. Agent Ecosystem
- **Agent Registration**: Set default trust level based on agent type
- **Role Assignment**: Automatically assign `agent` or `external_agent` roles
- **Policy Inheritance**: System-wide policies for agent categories

### 4. Administrative Interfaces
- **Policy Review Dashboard**: View and manage queued policies
- **Trust Level Management**: Manual trust adjustment interface
- **Audit Reporting**: Compliance and forensic analysis

## Security Considerations

### 1. Principle of Least Privilege
- Default deny stance
- Explicit allow policies required for any access
- Temporal policies for temporary access needs

### 2. Defense in Depth
- Database constraints prevent invalid trust levels
- Application-level policy evaluation
- Audit logging for forensic analysis
- Regular review of low-confidence policies

### 3. API Security
- Anthropic API key stored in `~/.secrets/`
- Environment variable configuration
- No hardcoded credentials in scripts

### 4. Database Security
- PostgreSQL connection with SCRAM authentication
- No direct table modifications – use provided functions
- Audit triggers on critical tables

### 5. Policy Validation
- Schema constraints enforce valid policy types/actions
- Confidence thresholds prevent ambiguous policy application
- Original text preservation for context verification

## Performance Considerations

### Indexing Strategy
- Indexes on `security_policies` for common query patterns:
  - `entity_id` + `enabled` + `policy_type`
  - `role_id` + `enabled` + `policy_type`
  - `priority` DESC for evaluation ordering
- Partial indexes for active policies only (`WHERE enabled = TRUE`)

### Policy Evaluation Optimization
- Function `check_policy()` optimized for single query evaluation
- Materialized views for frequently accessed security summaries
- Connection pooling for high-volume message processing

### Collector Performance
- Pre-filter regex reduces unnecessary API calls
- Batch processing of multiple policies per message
- Async processing for non-blocking operation

## Deployment Architecture

### Single-Node Deployment
```
Application Layer → PostgreSQL (nova_memory)
       ↓
  Policy Collector
       ↓
  Claude API (external)
```

### Multi-Node Considerations
- Shared PostgreSQL instance for all nodes
- Centralized policy storage for consistent enforcement
- Distributed collectors with shared audit log
- Message deduplication for policy extraction

## Future Extensions

### 1. Policy Inheritance
- Role hierarchy with permission inheritance
- Group-based policies (entities→groups→roles)
- Context-aware policies (time, location, device)

### 2. Advanced Pattern Matching
- Machine learning for policy statement detection
- Multi-model extraction (Claude + local models)
- Contextual disambiguation using agent memory

### 3. Integration Enhancements
- Webhook notifications for policy changes
- Real-time policy synchronization across nodes
- Graphical policy management interface

### 4. Compliance Features
- Policy versioning and rollback
- Compliance reporting (GDPR, HIPAA, etc.)
- Automated policy review scheduling

## Conclusion

NOVA Security provides a robust, extensible security foundation for the NOVA agent ecosystem. By combining traditional RBAC with AI-powered policy extraction and PostgreSQL enforcement, it enables natural language security management while maintaining strict access control. The architecture supports both automated and human-in-the-loop workflows, balancing security with operational flexibility.