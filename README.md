# NOVA Security

Security infrastructure for NOVA: entity policies, trust management, and access control.

## Overview

This project provides hard-enforced security policies for entity interactions:

- **Trust Levels** - Graduated trust from untrusted (0) to admin (5)
- **Entity Roles** - Cumulative role assignments (user, operator, admin, agent, etc.)
- **Security Policies** - Structured rules for communication, information sharing, action permissions
- **Policy Collector** - Active detection and enforcement of security policy statements
- **Enforcement Layer** - Hooks for message handling, response filtering, action authorization

## Architecture

```
Incoming Message
    │
    ├─► Policy Collector (active)
    │       ├─ Detect policy statements
    │       ├─ Resolve entities/roles
    │       ├─ Apply to security_policies table
    │       └─ Log changes
    │
    └─► Policy Enforcer
            ├─ Check communication policies
            ├─ Filter information sharing
            └─ Authorize actions
```

## Default Stance

**Deny until instructed otherwise.** Unknown entities have trust_level=0 and cannot communicate until explicitly permitted.

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| Schema | `schema/` | PostgreSQL tables and functions |
| Policy Collector | `scripts/collect-policies.sh` | Active policy detection |
| Enforcer | `lib/enforcer.py` | Policy enforcement library |
| Docs | `docs/` | Specifications and design docs |

## Quick Start

```bash
# Apply schema
psql -d nova_memory -f schema/001-trust-levels.sql
psql -d nova_memory -f schema/002-entity-roles.sql
psql -d nova_memory -f schema/003-security-policies.sql

# Run collector (typically called by hook)
./scripts/collect-policies.sh "policy statement text"
```

## Related Projects

- [nova_memory](../docs/) - Memory database (entities, facts, events)
- [openclaw](../openclaw/) - Gateway and message handling

---

*Private repository. Security-sensitive code.*
