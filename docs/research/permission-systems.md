# Permission and Access Control Systems Research
**Research for NOVA Security Implementation**  
*Date: 2026-02-09*

## Executive Summary

This document analyzes proven permission and access control systems to inform the design of NOVA Security, an AI agent security policy system with entity trust levels, cumulative roles, and policy enforcement. Key findings suggest a hybrid approach combining PostgreSQL Row-Level Security (RLS) for data-layer enforcement, role-based cumulative permissions, and explicit allow-list policies with audit logging.

---

## 1. Unix Filesystem Permissions

### 1.1 Classic rwx Model

**Core Concept:** Unix permissions use a simple but powerful 9-bit model for each file/directory:
- **r** (read) - 4
- **w** (write) - 2  
- **x** (execute) - 1

Applied to three categories:
- **User (owner)** - The file's owner
- **Group** - Members of the file's group
- **Other** - Everyone else

**Example:** `rwxr-xr--` (754)
- Owner: read, write, execute
- Group: read, execute
- Other: read only

### 1.2 Permission Composition

**How it Works:**
1. **Identity-first evaluation:** System checks if you're the owner first, then group, then other
2. **First match wins:** If you're the owner, only owner permissions apply (even if group/other have more)
3. **No accumulation within categories:** You don't get to "combine" user+group+other

**Key Insight:** This is NOT cumulative across categories, but it IS cumulative across groups.

### 1.3 Cumulative Group Membership

A user can belong to multiple groups simultaneously:
- Primary group (set in `/etc/passwd`)
- Secondary groups (set in `/etc/group`)

**Access granted if ANY of your groups have permission.** This is where Unix becomes cumulative.

**Example:**
```bash
User 'alice' is in groups: developers, admins, researchers
File permissions: rwxrwx--- owned by root:admins
Result: Alice can read/write/execute because she's in 'admins'
```

### 1.4 Special Bits: setuid, setgid, sticky

**setuid (Set User ID)** - 4000
- When set on executable: runs with owner's privileges, not executor's
- Example: `/usr/bin/passwd` runs as root so users can change passwords in `/etc/shadow`
- **Security risk:** Extremely dangerous if misconfigured; heavily scrutinized

**setgid (Set Group ID)** - 2000
- On executables: runs with file's group privileges
- On directories: new files inherit the directory's group (not creator's primary group)
- Useful for shared project directories

**Sticky bit** - 1000
- On directories: only file owner (or root) can delete/rename files in that directory
- Example: `/tmp` (drwxrwxrwt) - everyone can write, but can't delete others' files
- Prevents malicious deletion in shared spaces

**Notation:** Special bits show as `s` (setuid/setgid) or `t` (sticky) in the execute position:
- `rwsr-xr-x` - setuid enabled
- `rwxr-sr-x` - setgid enabled
- `rwxrwxrwt` - sticky bit enabled

### 1.5 POSIX ACLs (Access Control Lists)

**Problem:** Sometimes the user/group/other model is too coarse.

**Solution:** Extended ACLs allow fine-grained per-user and per-group permissions:

```bash
# Grant specific user read access
setfacl -m u:bob:r-- file.txt

# Grant specific group write access
setfacl -m g:analysts:rw- file.txt

# View ACLs
getfacl file.txt
```

**Output:**
```
# file: file.txt
# owner: alice
# group: developers
user::rw-
user:bob:r--
group::r--
group:analysts:rw-
mask::rw-
other::---
```

**Key Concepts:**
- **Mask:** Maximum effective permissions for named users/groups and group class
- **Default ACLs:** Inherited by new files in directory
- **Cumulative:** User gets the union of permissions from all applicable ACL entries

**Limitations:**
- Not all filesystems support ACLs
- Backup/restore tools may lose ACLs
- Can become complex to audit

### 1.6 Lessons for NOVA Security

✅ **Apply:**
- **Simple base model:** Start with clear, understandable permission bits (read, write, execute, admin)
- **Cumulative groups:** Entity can have multiple roles; permissions union across all roles
- **Special escalation bits:** Equivalent to "allow impersonation" or "run as" privileges
- **First-match patterns:** Consider identity hierarchy (direct grant > role grant > public)

⚠️ **Avoid:**
- **Complex special bits:** setuid/setgid are notoriously dangerous; if we implement "run as," needs extreme scrutiny
- **Implicit inheritance:** Be explicit about what's inherited vs. what requires explicit grant

---

## 2. PostgreSQL Permission Model

PostgreSQL offers one of the most sophisticated permission systems for data management, with GRANT/REVOKE, role inheritance, and Row-Level Security (RLS).

### 2.1 GRANT/REVOKE System

**Basic Syntax:**
```sql
GRANT privilege_type ON object TO role [WITH GRANT OPTION];
REVOKE privilege_type ON object FROM role;
```

**Privilege Types:**
- **SELECT** - Read data
- **INSERT** - Add new rows
- **UPDATE** - Modify existing rows
- **DELETE** - Remove rows
- **TRUNCATE** - Empty table
- **REFERENCES** - Create foreign keys
- **TRIGGER** - Create triggers
- **ALL PRIVILEGES** - Grant everything available for object type

**Column-Level Permissions:**
```sql
-- Grant read access only to specific columns
GRANT SELECT (user_name, email) ON users TO public;

-- Grant update only on safe columns
GRANT UPDATE (phone, address) ON users TO user_role;
```

**Key Behaviors:**
- **Additive:** Multiple GRANTs accumulate; you get the union
- **Owner privileges:** Object owner has all privileges by default, can't be revoked
- **PUBLIC role:** Special role representing "everyone"
- **WITH GRANT OPTION:** Allows grantee to grant same privilege to others

### 2.2 Role Inheritance and Membership

PostgreSQL unified users and groups into "roles" (as of 8.1).

**Creating Roles:**
```sql
-- Role that can login
CREATE ROLE alice WITH LOGIN PASSWORD 'secret';

-- Group role (can't login)
CREATE ROLE developers;

-- Grant membership
GRANT developers TO alice;
```

**Inheritance Control:**
```sql
-- Role with inheritance (default)
CREATE ROLE alice WITH INHERIT;

-- When alice is granted developers, she automatically inherits
-- all privileges granted to developers

-- Role without inheritance
CREATE ROLE bob WITH NOINHERIT;

-- Bob must explicitly SET ROLE developers to use those privileges
SET ROLE developers;
```

**Membership Options (PostgreSQL 16+):**
```sql
GRANT role_name TO user_name WITH {
  ADMIN TRUE|FALSE,    -- Can grant role to others
  INHERIT TRUE|FALSE,  -- Automatically inherit role's privileges
  SET TRUE|FALSE       -- Can SET ROLE to this role
};
```

**Example:**
```sql
CREATE ROLE admins;
CREATE ROLE operators;
CREATE ROLE alice;

-- Alice inherits admins, can SET ROLE to operators
GRANT admins TO alice WITH INHERIT TRUE, SET TRUE;
GRANT operators TO alice WITH INHERIT FALSE, SET TRUE;

-- Alice automatically has admin privileges
-- Alice must explicitly: SET ROLE operators; to use operator privileges
```

### 2.3 Row-Level Security (RLS)

**The Game-Changer:** RLS allows policy enforcement at the database level, automatically filtering rows based on the current user.

**Enabling RLS:**
```sql
ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;
```

**When enabled:**
- **Default-deny:** If no policy exists, no rows are visible/modifiable
- **Applies to non-owners:** Table owner typically bypasses RLS (unless FORCE ROW LEVEL SECURITY)
- **Superusers bypass:** Unless explicitly forced

**Creating Policies:**
```sql
CREATE POLICY policy_name ON table_name
  [FOR {ALL | SELECT | INSERT | UPDATE | DELETE}]
  [TO role_name]
  [USING (condition)]        -- Which rows are visible
  [WITH CHECK (condition)];  -- Which rows can be inserted/updated
```

### 2.4 RLS Policy Examples

**Example 1: Users See Only Their Own Data**
```sql
CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  owner TEXT NOT NULL,
  title TEXT,
  content TEXT
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_isolation ON documents
  USING (owner = current_user);
```

Result: Each user sees only their own documents. Simple and effective.

**Example 2: Hierarchical Access by Trust Level**
```sql
CREATE TABLE entities (
  id SERIAL PRIMARY KEY,
  name TEXT,
  trust_level INT -- 1=low, 2=medium, 3=high
);

CREATE TABLE users (
  username TEXT PRIMARY KEY,
  trust_level INT
);

CREATE TABLE data (
  id SERIAL PRIMARY KEY,
  content TEXT,
  required_trust_level INT
);

ALTER TABLE data ENABLE ROW LEVEL SECURITY;

-- Users can see data at or below their trust level
CREATE POLICY trust_filter ON data FOR SELECT
  USING (
    required_trust_level <= (
      SELECT trust_level FROM users WHERE username = current_user
    )
  );
```

**Example 3: Permissive vs. Restrictive Policies**

PostgreSQL supports two policy types:
- **PERMISSIVE (default):** Combined with OR - any matching policy grants access
- **RESTRICTIVE:** Combined with AND - all must pass

```sql
-- Permissive: user can see their own rows OR public rows
CREATE POLICY see_own ON documents FOR SELECT
  USING (owner = current_user);

CREATE POLICY see_public ON documents FOR SELECT
  USING (is_public = true);

-- Result: User sees rows where (owner = user) OR (is_public = true)

-- Restrictive: admins only over local connection
CREATE POLICY admin_local_only ON sensitive_data 
  AS RESTRICTIVE TO admin_role
  USING (pg_catalog.inet_client_addr() IS NULL);

-- Result: Admins must satisfy (other policies) AND (local connection)
```

**Example 4: Multi-Role Access**
```sql
-- Entity has multiple roles, cumulative permissions
CREATE TABLE entity_roles (
  entity_id TEXT,
  role_name TEXT,
  PRIMARY KEY (entity_id, role_name)
);

CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  content TEXT,
  required_role TEXT
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY role_access ON documents FOR SELECT
  USING (
    required_role IN (
      SELECT role_name FROM entity_roles 
      WHERE entity_id = current_user
    )
  );
```

### 2.5 RLS Best Practices & Gotchas

**✅ Best Practices:**
1. **Always enable RLS on sensitive tables** - Defense in depth
2. **Use RESTRICTIVE policies for security constraints** - Network source, time windows, MFA status
3. **Separate USING and WITH CHECK** - Allow read of existing data, but restrict what can be created
4. **Keep policies simple** - Complex sub-SELECTs can have performance impact and race conditions
5. **Test as different users** - `SET ROLE username;` to verify policies

**⚠️ Gotchas:**

**Race Conditions with Sub-SELECTs:**
```sql
-- DANGEROUS: Concurrent transactions can see stale privilege data
CREATE POLICY check_privilege ON data
  USING (
    (SELECT access_level FROM user_privileges WHERE user = current_user) >= data.sensitivity
  );

-- If user_privileges changes mid-query, policy may evaluate against old data
```

**Solution:** Use `FOR UPDATE` or `FOR SHARE` in sub-SELECTs, or lock referenced tables.

**Referential Integrity Bypasses RLS:**
- Foreign key checks, unique constraints always bypass RLS
- Can create "covert channels" - try to insert FK reference, error reveals row exists
- Careful schema design needed

**Performance:**
- Complex policies with sub-SELECTs can be slow
- Consider materialized views or denormalized privilege cache

### 2.6 Applying PostgreSQL RLS to NOVA Security

**Recommended Architecture:**

```sql
-- Entity trust levels
CREATE TABLE entities (
  entity_id TEXT PRIMARY KEY,
  trust_level INT CHECK (trust_level IN (1, 2, 3, 4, 5)),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Role definitions
CREATE TABLE roles (
  role_name TEXT PRIMARY KEY,
  description TEXT
);

-- Entity role memberships (cumulative)
CREATE TABLE entity_roles (
  entity_id TEXT REFERENCES entities(entity_id),
  role_name TEXT REFERENCES roles(role_name),
  granted_at TIMESTAMPTZ DEFAULT now(),
  granted_by TEXT,
  PRIMARY KEY (entity_id, role_name)
);

-- Policies define what roles can do
CREATE TABLE policies (
  policy_id SERIAL PRIMARY KEY,
  resource_type TEXT NOT NULL, -- 'file', 'message', 'tool', etc.
  resource_pattern TEXT,       -- Glob or regex pattern
  action TEXT NOT NULL,        -- 'read', 'write', 'execute'
  required_role TEXT REFERENCES roles(role_name),
  min_trust_level INT,
  effect TEXT CHECK (effect IN ('allow', 'deny')),
  priority INT DEFAULT 0       -- Higher priority evaluated first
);

-- Apply RLS to sensitive resources
CREATE TABLE messages (
  message_id SERIAL PRIMARY KEY,
  content TEXT,
  channel TEXT,
  author TEXT,
  required_trust_level INT DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

-- Policy: Entity can read messages at or below their trust level
CREATE POLICY message_trust_filter ON messages FOR SELECT
  USING (
    required_trust_level <= (
      SELECT trust_level FROM entities WHERE entity_id = current_user
    )
  );

-- Policy: Entity must have 'message_sender' role to insert
CREATE POLICY message_send_permission ON messages FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM entity_roles 
      WHERE entity_id = current_user 
      AND role_name = 'message_sender'
    )
  );
```

**Query Pattern:**
```sql
-- Check if entity can perform action on resource
CREATE FUNCTION can_perform_action(
  p_entity_id TEXT,
  p_resource_type TEXT,
  p_resource_path TEXT,
  p_action TEXT
) RETURNS BOOLEAN AS $$
DECLARE
  v_trust_level INT;
  v_allowed BOOLEAN := FALSE;
BEGIN
  -- Get entity trust level
  SELECT trust_level INTO v_trust_level 
  FROM entities WHERE entity_id = p_entity_id;
  
  -- Check policies (cumulative roles, priority order)
  SELECT COALESCE(bool_or(effect = 'allow'), FALSE) INTO v_allowed
  FROM policies p
  WHERE p.resource_type = p_resource_type
    AND (p.resource_pattern IS NULL OR p_resource_path ~ p.resource_pattern)
    AND p.action = p_action
    AND (p.min_trust_level IS NULL OR v_trust_level >= p.min_trust_level)
    AND (p.required_role IS NULL OR EXISTS (
      SELECT 1 FROM entity_roles er
      WHERE er.entity_id = p_entity_id
      AND er.role_name = p.required_role
    ))
  ORDER BY p.priority DESC;
  
  RETURN v_allowed;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

---

## 3. Other Notable Permission Systems

### 3.1 SELinux & AppArmor: MAC vs DAC

**DAC (Discretionary Access Control):**
- Unix/PostgreSQL are DAC systems
- **Owner controls access** - File owner decides who can access
- Flexible, user-driven, but vulnerable to Trojan horses (compromised user = compromised files)

**MAC (Mandatory Access Control):**
- System enforces access rules; users can't override
- **SELinux:** Label-based, every process and file has security context (user:role:type:level)
- **AppArmor:** Path-based, profiles define what files/capabilities a program can access

**SELinux Example:**
```bash
# Every file has a label: user:role:type:level
ls -Z /var/www/html/index.html
unconfined_u:object_r:httpd_sys_content_t:s0 /var/www/html/index.html

# Apache process runs with httpd_t type
ps -eZ | grep httpd
system_u:system_r:httpd_t:s0 1234 ? httpd

# Policy: httpd_t can read httpd_sys_content_t
# Even if file is world-readable, policy must allow
```

**Modes:**
- **Enforcing:** Blocks violations
- **Permissive:** Logs violations but allows
- **Disabled:** Off

**AppArmor Example:**
```bash
# Profile for /usr/bin/firefox
/usr/bin/firefox {
  # Allowed file access
  /home/*/.mozilla/** rw,
  /tmp/** rw,
  
  # Network access
  network inet stream,
  
  # Deny everything else (implicit)
}
```

**Key Insight for NOVA:**
- **MAC is "belt and suspenders"** - Even if NOVA's permission check has a bug, database-layer RLS provides mandatory enforcement
- **Consider AppArmor-style profiles for tools** - Define what files/network each tool can access
- **Defense in depth:** Application-layer + database-layer policies

### 3.2 AWS IAM: Policies and Conditions

AWS Identity and Access Management (IAM) uses JSON-based policies with rich conditional logic.

**Policy Structure:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "192.168.1.0/24"
        },
        "DateGreaterThan": {
          "aws:CurrentTime": "2026-01-01T00:00:00Z"
        }
      }
    }
  ]
}
```

**Key Concepts:**

**Effect:** `Allow` or `Deny`

**Action:** What can be done (e.g., `s3:GetObject`, `ec2:StartInstances`)

**Resource:** What it applies to (ARN - Amazon Resource Name)

**Condition:** Context-based constraints:
- IP address
- Time of day
- MFA status
- Request parameters
- Tags on resources

**Evaluation Logic:**
1. **Default deny** - Start with implicit deny
2. **Explicit deny wins** - Any explicit deny overrides allows
3. **Explicit allow required** - Must have explicit allow to proceed

**Policy Types:**
- **Identity-based:** Attached to users/groups/roles
- **Resource-based:** Attached to resources (S3 bucket policies)
- **Permission boundaries:** Maximum permissions a user can have
- **Service control policies (SCPs):** Organization-wide guardrails

**Lessons for NOVA:**
- **Conditions are powerful** - Time windows, network source, MFA status, resource tags
- **Explicit deny is nuclear** - Consider having both allow and deny policies, with deny always winning
- **Resource-based policies** - Some resources (files, tools) might have their own access policies
- **Boundaries:** Set maximum possible permissions for a role, even if granted more

**Example NOVA Policy:**
```json
{
  "statement": [
    {
      "effect": "allow",
      "action": "message:send",
      "resource": "channel:*",
      "condition": {
        "trust_level_gte": 3,
        "time_of_day_between": ["09:00", "17:00"],
        "roles_include_any": ["communicator", "admin"]
      }
    },
    {
      "effect": "deny",
      "action": "file:delete",
      "resource": "file:/critical/**",
      "condition": {
        "description": "No one can delete critical files"
      }
    }
  ]
}
```

### 3.3 OAuth 2.0 Scopes

OAuth is an authorization framework for delegated access, commonly used for API access.

**Core Concept: Scopes**

A scope is a permission string defining what access is granted:

```
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/gmail.send
https://www.googleapis.com/auth/calendar
```

**Key Properties:**
- **Coarse-grained:** Each scope grants access to a capability or resource group
- **Delegated:** User grants app access to their resources
- **Token-bound:** Access token carries scopes; API checks token

**Example Flow:**
1. App requests: `scope=gmail.readonly gmail.send`
2. User approves
3. App receives token with granted scopes
4. App calls API with token
5. API validates token and checks if required scope is present

**Lessons for NOVA:**
- **Simple scope strings** - Easy to reason about, easy to audit
- **Explicit consent** - User/admin explicitly grants entity specific capabilities
- **Token-based** - Could issue JWT tokens to entities with embedded scope claims
- **Revocation** - OAuth supports token revocation; we should support role revocation

**Example NOVA Scopes:**
```
nova:message:read          # Read messages
nova:message:send          # Send messages
nova:file:read:workspace   # Read workspace files
nova:file:write:workspace  # Write workspace files
nova:tool:exec:browser     # Execute browser tool
nova:admin:*               # All admin capabilities
```

**Scope Check:**
```python
def require_scope(required_scope):
    def decorator(func):
        def wrapper(entity, *args, **kwargs):
            if required_scope in entity.granted_scopes:
                return func(entity, *args, **kwargs)
            else:
                raise PermissionDenied(f"Missing scope: {required_scope}")
        return wrapper
    return decorator

@require_scope("nova:message:send")
def send_message(entity, channel, text):
    # Send message
    pass
```

### 3.4 Capability-Based Security

**Concept:** Instead of asking "who are you and what can you do?", we ask "do you have a capability (unforgeable token) that grants this access?"

**Traditional ACL:**
```
File: /etc/passwd
ACL: root:rwx, admin:r--, other:r--
Access check: Who is requesting? Do they have permission?
```

**Capability-Based:**
```
Capability: <unforgeable_token_granting_read_access_to_/etc/passwd>
Access check: Present valid capability? If yes, access granted.
```

**Properties:**
- **Unforgeable:** Capabilities are cryptographically secured
- **Delegatable:** Holder can create derived capabilities with subset of rights
- **Revocable:** Issuer can invalidate capability
- **No ambient authority:** Just being "user X" doesn't grant access; you must possess the capability

**Examples:**
- **Plan 9 from Bell Labs:** File descriptors are capabilities; if you have an open FD, you can use it
- **FreeBSD Capsicum:** Processes enter "capability mode" where only explicitly passed FDs are accessible
- **HYDRA, KeyKOS, seL4:** Operating systems built on capabilities

**Delegation Example:**
```
Alice has: Capability(file=/report.pdf, rights=read+write+delegate)

Alice creates derived capability for Bob:
  Capability(file=/report.pdf, rights=read, delegated_by=Alice)

Bob can read but not write or further delegate.
```

**Lessons for NOVA:**
- **Consider capability tokens for tool access** - Generate signed JWT granting specific tool with specific parameters
- **Time-limited capabilities** - Auto-expiring tokens reduce revocation complexity
- **Delegation chains** - Track who delegated what to whom (audit trail)
- **Avoid ambient authority** - Don't assume entity has access just because they're "trust level 4"; require explicit grant

**Example NOVA Capability:**
```json
{
  "iss": "nova-security",
  "sub": "entity:abc123",
  "cap": {
    "tool": "browser",
    "action": "navigate",
    "max_domains": ["example.com", "*.example.org"],
    "expires": "2026-02-10T00:00:00Z"
  },
  "delegated_by": "entity:admin",
  "signature": "..."
}
```

---

## 4. Application to NOVA Security Design

### 4.1 Hybrid Approach Recommendation

**Combine the best of all worlds:**

1. **PostgreSQL RLS for data-layer enforcement** (MAC-like)
2. **Role-based cumulative permissions** (Unix groups + PostgreSQL roles)
3. **Explicit allow-list policies with conditions** (AWS IAM-style)
4. **Scope-based tool access** (OAuth-style)
5. **Capability tokens for delegation** (Capability-based)
6. **Audit logging** (Every access decision logged)

### 4.2 Policy Design: Allow-List vs. Deny-List

**Recommendation: Primarily allow-list, with explicit deny override**

**Rationale:**
- **Allow-list (default deny):**
  - ✅ Secure by default - New resources automatically protected
  - ✅ Explicit about what's permitted
  - ✅ Easier to audit (finite set of allows)
  - ❌ Requires policy for everything
  
- **Deny-list (default allow):**
  - ✅ Flexible, less configuration
  - ❌ Insecure by default - Forget to deny something? It's accessible
  - ❌ Hard to audit (must verify no dangerous allows)

**Hybrid Strategy:**
```
1. Default: DENY (implicit)
2. Evaluate all ALLOW policies (cumulative, OR-combined)
3. Evaluate all DENY policies (override, OR-combined)
4. If any explicit DENY matches: DENY
5. If any ALLOW matches and no DENY: ALLOW
6. Otherwise: DENY
```

**Example:**
```python
def check_access(entity, resource, action):
    # 1. Collect allow policies
    allow_policies = get_matching_policies(entity, resource, action, effect='allow')
    
    # 2. Collect deny policies
    deny_policies = get_matching_policies(entity, resource, action, effect='deny')
    
    # 3. Explicit deny wins
    if any(deny_policies):
        log_access_denied(entity, resource, action, reason='explicit_deny')
        return False
    
    # 4. Any allow grants access
    if any(allow_policies):
        log_access_granted(entity, resource, action, policies=allow_policies)
        return True
    
    # 5. Default deny
    log_access_denied(entity, resource, action, reason='no_allow_policy')
    return False
```

### 4.3 Handling Policy Conflicts

**Scenario:** Entity has multiple roles, roles have conflicting policies.

**Resolution Strategy (in order):**

1. **Explicit DENY always wins** - Any deny policy blocks access
2. **Within allows: highest specificity wins**
   - Exact match > pattern match > wildcard
3. **Priority field** - Policies have numeric priority, higher evaluated first
4. **Tie-breaker: most restrictive**

**Example:**
```
Entity: agent-1
Roles: [researcher, communicator]

Policies:
- researcher → ALLOW message:send to channel:research-*
- communicator → ALLOW message:send to channel:*
- admin → DENY message:send to channel:critical

Result for channel:research-general → ALLOW (matches researcher, communicator)
Result for channel:public → ALLOW (matches communicator)
Result for channel:critical → DENY (explicit deny, even if roles allow)
```

### 4.4 Leveraging PostgreSQL RLS for Entity-Level Data Access

**Recommended Pattern:**

```sql
-- Main entity context (set once per request)
CREATE FUNCTION set_entity_context(p_entity_id TEXT, p_trust_level INT, p_roles TEXT[])
RETURNS VOID AS $$
BEGIN
  -- Store in session variables
  PERFORM set_config('app.entity_id', p_entity_id, false);
  PERFORM set_config('app.trust_level', p_trust_level::text, false);
  PERFORM set_config('app.roles', array_to_string(p_roles, ','), false);
END;
$$ LANGUAGE plpgsql;

-- Use in RLS policies
CREATE POLICY entity_isolation ON sensitive_table
  USING (
    owner = current_setting('app.entity_id')
    OR required_trust_level <= current_setting('app.trust_level')::int
    OR required_role = ANY(string_to_array(current_setting('app.roles'), ','))
  );
```

**Workflow:**
1. Entity makes request
2. Application validates entity, looks up roles and trust level
3. Application calls `set_entity_context()`
4. Application performs query
5. PostgreSQL RLS automatically filters rows
6. Application returns results

**Benefits:**
- **Defense in depth:** Even if app-layer checks fail, database enforces
- **Consistent enforcement:** Can't accidentally bypass with raw SQL
- **Performance:** Database-native filtering is fast
- **Audit:** Database can log all RLS decisions

### 4.5 Audit Logging Patterns

**What to Log:**
1. **All access decisions** (allow, deny)
2. **Who** (entity_id, roles, trust_level)
3. **What** (resource_type, resource_path, action)
4. **When** (timestamp, timezone)
5. **Why** (matching policy_id or reason for denial)
6. **Context** (session_id, ip_address, user_agent)

**Schema:**
```sql
CREATE TABLE access_log (
  log_id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT now(),
  entity_id TEXT NOT NULL,
  entity_roles TEXT[],
  trust_level INT,
  resource_type TEXT NOT NULL,
  resource_path TEXT,
  action TEXT NOT NULL,
  decision TEXT CHECK (decision IN ('allow', 'deny')),
  policy_id INT REFERENCES policies(policy_id),
  deny_reason TEXT,
  context JSONB,
  session_id TEXT,
  ip_address INET
);

-- Index for efficient queries
CREATE INDEX idx_access_log_entity ON access_log(entity_id, timestamp DESC);
CREATE INDEX idx_access_log_resource ON access_log(resource_type, resource_path, timestamp DESC);
CREATE INDEX idx_access_log_decision ON access_log(decision, timestamp DESC) WHERE decision = 'deny';
```

**Querying:**
```sql
-- All denied accesses in last 24h
SELECT * FROM access_log
WHERE decision = 'deny' 
AND timestamp > now() - interval '24 hours'
ORDER BY timestamp DESC;

-- Entity's activity
SELECT resource_type, action, COUNT(*), 
       COUNT(*) FILTER (WHERE decision = 'allow') as allowed,
       COUNT(*) FILTER (WHERE decision = 'deny') as denied
FROM access_log
WHERE entity_id = 'agent-1'
AND timestamp > now() - interval '7 days'
GROUP BY resource_type, action;

-- Anomaly detection: entity accessing unusual resources
WITH entity_baseline AS (
  SELECT entity_id, resource_type, COUNT(*) as access_count
  FROM access_log
  WHERE timestamp > now() - interval '30 days'
  GROUP BY entity_id, resource_type
)
SELECT al.entity_id, al.resource_type, al.resource_path
FROM access_log al
LEFT JOIN entity_baseline eb ON al.entity_id = eb.entity_id 
  AND al.resource_type = eb.resource_type
WHERE eb.access_count IS NULL  -- New resource type for this entity
AND al.timestamp > now() - interval '1 hour';
```

### 4.6 Implementation Checklist

**Phase 1: Core Infrastructure**
- [ ] Entity and role tables in PostgreSQL
- [ ] Policy definition table with allow/deny, conditions, priority
- [ ] `check_access()` function implementing policy evaluation logic
- [ ] Session context management (`set_entity_context()`)
- [ ] Access log table and logging function

**Phase 2: RLS Policies**
- [ ] Enable RLS on all sensitive tables
- [ ] Create trust-level-based policies
- [ ] Create role-based policies
- [ ] Create restrictive policies for special constraints (time, network, etc.)
- [ ] Test policies thoroughly with different entity contexts

**Phase 3: Application Integration**
- [ ] Middleware to set entity context on every request
- [ ] Permission checks before sensitive operations
- [ ] Tool access scope enforcement
- [ ] Audit logging integration
- [ ] Error handling and user-friendly permission denied messages

**Phase 4: Administration & Monitoring**
- [ ] Admin UI for managing entities, roles, policies
- [ ] Policy testing/simulation tool ("what-if" access checks)
- [ ] Audit log dashboard
- [ ] Alerting for suspicious access patterns
- [ ] Regular policy review and cleanup

---

## 5. Specific PostgreSQL RLS Examples for NOVA

### 5.1 Trust-Level-Based Document Access

```sql
CREATE TABLE documents (
  doc_id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT,
  owner_entity_id TEXT NOT NULL,
  required_trust_level INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Policy: Can read if trust level sufficient
CREATE POLICY doc_trust_read ON documents FOR SELECT
  USING (
    required_trust_level <= current_setting('app.trust_level')::int
  );

-- Policy: Can only create docs at or below own trust level
CREATE POLICY doc_trust_write ON documents FOR INSERT
  WITH CHECK (
    required_trust_level <= current_setting('app.trust_level')::int
    AND owner_entity_id = current_setting('app.entity_id')
  );

-- Policy: Can only update own docs
CREATE POLICY doc_owner_update ON documents FOR UPDATE
  USING (owner_entity_id = current_setting('app.entity_id'));
```

### 5.2 Role-Based Tool Access

```sql
CREATE TABLE tool_executions (
  exec_id SERIAL PRIMARY KEY,
  entity_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  parameters JSONB,
  result JSONB,
  executed_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE tool_permissions (
  tool_name TEXT PRIMARY KEY,
  required_role TEXT NOT NULL
);

INSERT INTO tool_permissions VALUES
  ('browser', 'web_researcher'),
  ('exec', 'system_admin'),
  ('message', 'communicator');

ALTER TABLE tool_executions ENABLE ROW LEVEL SECURITY;

-- Policy: Can insert tool execution if have required role
CREATE POLICY tool_exec_role_check ON tool_executions FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM tool_permissions tp
      WHERE tp.tool_name = NEW.tool_name
      AND tp.required_role = ANY(string_to_array(current_setting('app.roles'), ','))
    )
  );

-- Policy: Can read own executions or if admin
CREATE POLICY tool_exec_read ON tool_executions FOR SELECT
  USING (
    entity_id = current_setting('app.entity_id')
    OR 'admin' = ANY(string_to_array(current_setting('app.roles'), ','))
  );
```

### 5.3 Time-Window-Based Access

```sql
CREATE TABLE scheduled_resources (
  resource_id SERIAL PRIMARY KEY,
  resource_name TEXT NOT NULL,
  allowed_start_time TIME NOT NULL,  -- e.g., '09:00'
  allowed_end_time TIME NOT NULL,    -- e.g., '17:00'
  content TEXT
);

ALTER TABLE scheduled_resources ENABLE ROW LEVEL SECURITY;

-- Policy: Can access only during allowed time window
CREATE POLICY time_window_access ON scheduled_resources FOR SELECT
  USING (
    LOCALTIME BETWEEN allowed_start_time AND allowed_end_time
  );

-- Restrictive policy: Never allow access outside business hours
CREATE POLICY business_hours_only ON scheduled_resources 
  AS RESTRICTIVE
  USING (
    EXTRACT(DOW FROM LOCALTIMESTAMP) BETWEEN 1 AND 5  -- Mon-Fri
    AND LOCALTIME BETWEEN '09:00' AND '17:00'
  );
```

### 5.4 Network-Based Access (IP Restriction)

```sql
-- Requires custom function to get client IP in application context
CREATE FUNCTION get_client_ip() RETURNS INET AS $$
  SELECT current_setting('app.client_ip')::INET;
$$ LANGUAGE SQL STABLE;

CREATE TABLE network_restricted_data (
  data_id SERIAL PRIMARY KEY,
  content TEXT,
  allowed_network CIDR  -- e.g., '192.168.1.0/24'
);

ALTER TABLE network_restricted_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY network_restriction ON network_restricted_data FOR SELECT
  USING (
    get_client_ip() << allowed_network  -- IP is within CIDR block
  );
```

### 5.5 Cumulative Multi-Role Access

```sql
CREATE TABLE project_files (
  file_id SERIAL PRIMARY KEY,
  project_name TEXT NOT NULL,
  filename TEXT NOT NULL,
  content TEXT,
  required_roles TEXT[]  -- Array: ['developer', 'tester']
);

ALTER TABLE project_files ENABLE ROW LEVEL SECURITY;

-- Policy: Can access if entity has ANY of the required roles
CREATE POLICY multi_role_access ON project_files FOR SELECT
  USING (
    required_roles && string_to_array(current_setting('app.roles'), ',')
    -- && is array overlap operator: returns true if arrays share any element
  );
```

---

## 6. Key Recommendations for NOVA Security

### 6.1 Architectural Principles

1. **Defense in Depth**
   - Application-layer permission checks
   - Database-layer RLS enforcement
   - Schema-level constraints (CHECK, FK)
   - Audit logging at every layer

2. **Secure by Default**
   - Default deny unless explicitly allowed
   - Explicit deny overrides any allow
   - New entities start with minimal permissions
   - RLS enabled by default on sensitive tables

3. **Cumulative Roles**
   - Entities can have multiple roles
   - Permissions are union (OR) across all roles
   - Use PostgreSQL's role inheritance where appropriate
   - Track role grants with timestamps and grantor

4. **Explicit Policy Language**
   - Policies clearly state effect (allow/deny), resource, action, conditions
   - Avoid ambiguity - "can execute browser on *.example.com"
   - Version policies, track changes
   - Regular policy reviews and cleanup

5. **Audit Everything**
   - Log all access decisions (allow and deny)
   - Include context (roles, trust level, IP, time)
   - Make logs queryable and alertable
   - Retain for compliance and forensics

### 6.2 Technical Recommendations

✅ **Use PostgreSQL RLS as primary enforcement mechanism**
- Mandatory enforcement, can't be bypassed by buggy app code
- Performance is good with simple policies
- Built-in, mature, well-tested

✅ **Implement AWS IAM-style conditional policies**
- Trust level, roles, time, network, MFA status
- Flexible enough for complex scenarios
- Easy to reason about and audit

✅ **Adopt OAuth-style scopes for tool access**
- Simple string-based permissions
- Easy to display to users ("grant access to browser?")
- Can be encoded in JWT tokens

✅ **Consider capability tokens for delegation**
- Time-limited, signed tokens for specific actions
- Reduces need for complex role hierarchies
- Natural fit for "agent asks user for permission" flow

✅ **Trust levels as coarse-grained filter**
- 1-5 scale, with clear definitions
- Used as first-pass filter before detailed policy checks
- Easy to understand and communicate

⚠️ **Avoid complex nested policy logic**
- Keep policies simple and testable
- Prefer multiple simple policies over one complex policy
- Beware race conditions in sub-SELECTs

⚠️ **Don't rely solely on app-layer checks**
- Bugs happen; defense in depth essential
- Database RLS is your safety net

⚠️ **Watch performance on complex RLS policies**
- Profile queries with EXPLAIN
- Consider denormalized permission cache for hot paths
- Index foreign keys and policy lookup columns

### 6.3 Operational Recommendations

1. **Policy Testing Environment**
   - Staging database with production-like policies
   - "What-if" tool: "Would entity X be able to access resource Y?"
   - Automated policy regression tests

2. **Monitoring and Alerting**
   - Dashboard for denied accesses (spike might indicate attack or misconfiguration)
   - Alert on unusual access patterns (entity accessing new resource types)
   - Regular audit log reviews

3. **Policy Lifecycle Management**
   - Version control policies (Git repo)
   - Change approval process for policy modifications
   - Automated deployment with rollback capability
   - Regular policy cleanup (remove unused, consolidate similar)

4. **Documentation**
   - Clear role definitions ("researcher" means what?)
   - Trust level criteria (what does trust level 3 entail?)
   - Policy decision documentation (why this policy exists)
   - Runbooks for common permission issues

5. **Compliance and Forensics**
   - Retain audit logs per compliance requirements
   - Immutable log storage (append-only)
   - Regular compliance audits
   - Forensic analysis capability (who accessed what when)

---

## 7. Conclusion

NOVA Security should adopt a **hybrid permission model** combining:

- **PostgreSQL RLS** for mandatory data-layer enforcement
- **Role-based access control** with cumulative membership
- **Conditional policies** (trust level, time, network, roles)
- **Explicit allow-list with deny override**
- **Comprehensive audit logging**

This approach provides:
- ✅ Strong security defaults
- ✅ Flexibility for complex scenarios
- ✅ Database-level enforcement as safety net
- ✅ Clear audit trail
- ✅ Scalable and maintainable

Key patterns from existing systems:
- **Unix:** Cumulative group membership, special escalation bits
- **PostgreSQL:** RLS policies, role inheritance, column-level permissions
- **AWS IAM:** Conditional policies, explicit deny wins
- **OAuth:** Simple scope strings, delegated access
- **Capability-based:** Unforgeable tokens, time-limited delegation

**Next Steps:**
1. Implement entity/role/policy schema in PostgreSQL
2. Deploy RLS policies on sensitive tables
3. Build application-layer policy evaluation engine
4. Integrate audit logging
5. Create admin tools for policy management
6. Test thoroughly with various entity/role/trust-level combinations

---

## References

- [PostgreSQL Row Security Policies Documentation](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL GRANT Command Reference](https://www.postgresql.org/docs/current/sql-grant.html)
- [SELinux User's and Administrator's Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/)
- [AWS IAM Policy Evaluation Logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [OAuth 2.0 Specification (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)
- [Capability-Based Computer Systems (Levy, 1984)](http://www.cs.washington.edu/homes/levy/capabook/)

---

*Research compiled by: research-agent*  
*Date: 2026-02-09*  
*For: NOVA Security Implementation*
