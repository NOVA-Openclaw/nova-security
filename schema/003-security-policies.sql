-- Security Policies Schema
-- Hard-enforced security rules for entity interactions

-- Policy types enum (for documentation, not enforced at DB level)
COMMENT ON SCHEMA public IS 'Policy types: communication, information_sharing, action_permission, response_mode, data_access, delegation, trust_change, role_assignment';

CREATE TABLE IF NOT EXISTS security_policies (
    id SERIAL PRIMARY KEY,
    
    -- Who the policy applies to (at least one must be set)
    entity_id INTEGER REFERENCES entities(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES entity_roles(id) ON DELETE CASCADE,
    applies_to_all BOOLEAN DEFAULT FALSE,
    
    -- Policy definition
    policy_type VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL,  -- allow, deny, require_approval, log_only
    
    -- Policy targets/conditions
    target_entity_id INTEGER REFERENCES entities(id),  -- For relationship policies
    target_role_id INTEGER REFERENCES entity_roles(id),
    resource_pattern TEXT,  -- Regex/glob for resource-based policies
    conditions JSONB DEFAULT '{}',  -- Additional structured conditions
    
    -- Metadata
    priority INTEGER DEFAULT 100,  -- Higher = evaluated first
    enabled BOOLEAN DEFAULT TRUE,
    source TEXT,  -- How created: 'manual', 'extracted', 'inherited'
    source_message_id TEXT,  -- Original message that created this
    original_text TEXT,  -- Exact quote from source message
    confidence FLOAT DEFAULT 1.0,  -- Extraction confidence
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    created_by INTEGER REFERENCES entities(id),
    updated_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,  -- For temporal policies
    
    -- Constraints
    CONSTRAINT policy_has_subject CHECK (
        entity_id IS NOT NULL OR role_id IS NOT NULL OR applies_to_all
    ),
    CONSTRAINT valid_action CHECK (
        action IN ('allow', 'deny', 'require_approval', 'log_only')
    ),
    CONSTRAINT valid_policy_type CHECK (
        policy_type IN (
            'communication',
            'information_sharing', 
            'action_permission',
            'response_mode',
            'data_access',
            'delegation'
        )
    )
);

-- Indexes for fast policy lookups
CREATE INDEX IF NOT EXISTS idx_policies_entity ON security_policies(entity_id) WHERE entity_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policies_role ON security_policies(role_id) WHERE role_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policies_type ON security_policies(policy_type);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON security_policies(enabled) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_policies_expires ON security_policies(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policies_priority ON security_policies(priority DESC);

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_policy_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS policy_updated_at ON security_policies;
CREATE TRIGGER policy_updated_at
    BEFORE UPDATE ON security_policies
    FOR EACH ROW EXECUTE FUNCTION update_policy_timestamp();

-- Audit log for policy changes
CREATE TABLE IF NOT EXISTS policy_audit (
    id SERIAL PRIMARY KEY,
    policy_id INTEGER,  -- Can be NULL if policy was deleted
    action VARCHAR(20) NOT NULL,  -- created, updated, deleted, applied, denied
    old_values JSONB,
    new_values JSONB,
    performed_by INTEGER REFERENCES entities(id),
    source_message_id TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_audit_policy ON policy_audit(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_action ON policy_audit(action);
CREATE INDEX IF NOT EXISTS idx_policy_audit_time ON policy_audit(created_at DESC);

-- Function: check if action is allowed for entity
CREATE OR REPLACE FUNCTION check_policy(
    p_entity_id INTEGER,
    p_policy_type VARCHAR(50),
    p_resource TEXT DEFAULT NULL
) RETURNS TABLE(
    allowed BOOLEAN, 
    policy_id INTEGER, 
    action VARCHAR(20),
    reason TEXT
) AS $$
BEGIN
    RETURN QUERY
    WITH entity_roles AS (
        SELECT role_id FROM entity_role_assignments 
        WHERE entity_id = p_entity_id
          AND (expires_at IS NULL OR expires_at > NOW())
    )
    SELECT 
        CASE sp.action 
            WHEN 'allow' THEN TRUE 
            WHEN 'deny' THEN FALSE 
            WHEN 'require_approval' THEN NULL  -- Needs human decision
            WHEN 'log_only' THEN TRUE
        END as allowed,
        sp.id as policy_id,
        sp.action,
        'Policy #' || sp.id || ': ' || sp.action as reason
    FROM security_policies sp
    WHERE sp.enabled = TRUE
      AND (sp.expires_at IS NULL OR sp.expires_at > NOW())
      AND sp.policy_type = p_policy_type
      AND (
          sp.entity_id = p_entity_id
          OR sp.role_id IN (SELECT role_id FROM entity_roles)
          OR sp.applies_to_all = TRUE
      )
      AND (
          p_resource IS NULL 
          OR sp.resource_pattern IS NULL 
          OR p_resource ~ sp.resource_pattern
      )
    ORDER BY sp.priority DESC
    LIMIT 1;
    
    -- If no policy found, check trust level (deny by default for untrusted)
    IF NOT FOUND THEN
        RETURN QUERY
        SELECT 
            CASE WHEN e.trust_level >= 2 THEN TRUE ELSE FALSE END as allowed,
            NULL::INTEGER as policy_id,
            'default'::VARCHAR(20) as action,
            CASE WHEN e.trust_level >= 2 
                THEN 'Default allow (trust_level=' || e.trust_level || ')'
                ELSE 'Default deny (trust_level=' || e.trust_level || ')'
            END as reason
        FROM entities e
        WHERE e.id = p_entity_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function: check communication permission
CREATE OR REPLACE FUNCTION can_communicate(p_entity_id INTEGER)
RETURNS BOOLEAN AS $$
DECLARE
    v_result BOOLEAN;
BEGIN
    SELECT allowed INTO v_result FROM check_policy(p_entity_id, 'communication');
    RETURN COALESCE(v_result, FALSE);  -- Default deny
END;
$$ LANGUAGE plpgsql;

-- Function: create policy with audit
CREATE OR REPLACE FUNCTION create_policy(
    p_entity_id INTEGER,
    p_role_id INTEGER,
    p_policy_type VARCHAR(50),
    p_action VARCHAR(20),
    p_target_entity_id INTEGER DEFAULT NULL,
    p_resource_pattern TEXT DEFAULT NULL,
    p_priority INTEGER DEFAULT 100,
    p_expires_at TIMESTAMP DEFAULT NULL,
    p_source TEXT DEFAULT 'manual',
    p_source_message_id TEXT DEFAULT NULL,
    p_original_text TEXT DEFAULT NULL,
    p_confidence FLOAT DEFAULT 1.0,
    p_created_by INTEGER DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_policy_id INTEGER;
BEGIN
    INSERT INTO security_policies (
        entity_id, role_id, policy_type, action,
        target_entity_id, resource_pattern, priority,
        expires_at, source, source_message_id, original_text,
        confidence, created_by
    ) VALUES (
        p_entity_id, p_role_id, p_policy_type, p_action,
        p_target_entity_id, p_resource_pattern, p_priority,
        p_expires_at, p_source, p_source_message_id, p_original_text,
        p_confidence, p_created_by
    ) RETURNING id INTO v_policy_id;
    
    -- Audit log
    INSERT INTO policy_audit (policy_id, action, new_values, performed_by, source_message_id)
    VALUES (
        v_policy_id,
        'created',
        jsonb_build_object(
            'entity_id', p_entity_id,
            'role_id', p_role_id,
            'policy_type', p_policy_type,
            'action', p_action,
            'confidence', p_confidence
        ),
        p_created_by,
        p_source_message_id
    );
    
    RETURN v_policy_id;
END;
$$ LANGUAGE plpgsql;

-- View: all active policies with resolved names
CREATE OR REPLACE VIEW v_active_policies AS
SELECT 
    sp.id,
    sp.policy_type,
    sp.action,
    e.name as entity_name,
    r.name as role_name,
    te.name as target_entity_name,
    tr.name as target_role_name,
    sp.resource_pattern,
    sp.priority,
    sp.confidence,
    sp.expires_at,
    sp.original_text,
    sp.created_at
FROM security_policies sp
LEFT JOIN entities e ON sp.entity_id = e.id
LEFT JOIN entity_roles r ON sp.role_id = r.id
LEFT JOIN entities te ON sp.target_entity_id = te.id
LEFT JOIN entity_roles tr ON sp.target_role_id = tr.id
WHERE sp.enabled = TRUE
  AND (sp.expires_at IS NULL OR sp.expires_at > NOW())
ORDER BY sp.priority DESC, sp.created_at DESC;

-- View: entity security summary
CREATE OR REPLACE VIEW v_entity_security AS
SELECT 
    e.id as entity_id,
    e.name,
    e.type,
    e.trust_level,
    trust_level_name(e.trust_level) as trust_level_name,
    tl.can_communicate as trust_can_communicate,
    can_communicate(e.id) as policy_can_communicate,
    ARRAY_AGG(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL) as roles,
    COUNT(DISTINCT sp.id) as policy_count
FROM entities e
LEFT JOIN trust_levels tl ON e.trust_level = tl.level
LEFT JOIN entity_role_assignments era ON e.id = era.entity_id
LEFT JOIN entity_roles r ON era.role_id = r.id
LEFT JOIN security_policies sp ON sp.entity_id = e.id AND sp.enabled = TRUE
GROUP BY e.id, e.name, e.type, e.trust_level, tl.can_communicate;

COMMENT ON TABLE security_policies IS 'Hard-enforced security policies for entity interactions. Deny by default.';
COMMENT ON TABLE policy_audit IS 'Audit trail for all policy changes. Security-sensitive.';
