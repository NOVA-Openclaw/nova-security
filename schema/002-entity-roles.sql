-- Entity Roles Schema
-- Enables role-based policies: "Administrators can do X"
-- Roles are CUMULATIVE - an entity can hold multiple roles

CREATE TABLE IF NOT EXISTS entity_roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    min_trust_level INTEGER DEFAULT 0 REFERENCES trust_levels(level),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Default roles
INSERT INTO entity_roles (name, description, min_trust_level) VALUES
    ('user', 'Standard user with basic permissions', 2),
    ('operator', 'Can perform operational tasks', 3),
    ('admin', 'Full administrative access', 5),
    ('agent', 'Internal AI agent with defined capabilities', 3),
    ('external_agent', 'AI agent from external system', 2),
    ('service', 'Automated service or bot', 1)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    min_trust_level = EXCLUDED.min_trust_level;

-- Role assignments (junction table)
-- An entity can have MULTIPLE roles (cumulative model)
CREATE TABLE IF NOT EXISTS entity_role_assignments (
    entity_id INTEGER REFERENCES entities(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES entity_roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT NOW(),
    assigned_by INTEGER REFERENCES entities(id),
    expires_at TIMESTAMP,  -- Optional expiration
    notes TEXT,
    PRIMARY KEY (entity_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_entity ON entity_role_assignments(entity_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_role ON entity_role_assignments(role_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_expires ON entity_role_assignments(expires_at) 
    WHERE expires_at IS NOT NULL;

-- Helper function: get entity's roles
CREATE OR REPLACE FUNCTION entity_roles(p_entity_id INTEGER)
RETURNS TABLE(role_name VARCHAR(50), assigned_at TIMESTAMP, expires_at TIMESTAMP) AS $$
    SELECT r.name, era.assigned_at, era.expires_at
    FROM entity_role_assignments era
    JOIN entity_roles r ON era.role_id = r.id
    WHERE era.entity_id = p_entity_id
      AND (era.expires_at IS NULL OR era.expires_at > NOW());
$$ LANGUAGE SQL STABLE;

-- Helper function: check if entity has role
CREATE OR REPLACE FUNCTION entity_has_role(p_entity_id INTEGER, p_role_name VARCHAR(50))
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM entity_role_assignments era
        JOIN entity_roles r ON era.role_id = r.id
        WHERE era.entity_id = p_entity_id
          AND r.name = p_role_name
          AND (era.expires_at IS NULL OR era.expires_at > NOW())
    );
$$ LANGUAGE SQL STABLE;

-- Helper function: assign role to entity
CREATE OR REPLACE FUNCTION assign_role(
    p_entity_id INTEGER, 
    p_role_name VARCHAR(50),
    p_assigned_by INTEGER DEFAULT NULL,
    p_expires_at TIMESTAMP DEFAULT NULL,
    p_notes TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_role_id INTEGER;
BEGIN
    SELECT id INTO v_role_id FROM entity_roles WHERE name = p_role_name;
    IF v_role_id IS NULL THEN
        RAISE EXCEPTION 'Role % does not exist', p_role_name;
    END IF;
    
    INSERT INTO entity_role_assignments (entity_id, role_id, assigned_by, expires_at, notes)
    VALUES (p_entity_id, v_role_id, p_assigned_by, p_expires_at, p_notes)
    ON CONFLICT (entity_id, role_id) DO UPDATE SET
        expires_at = EXCLUDED.expires_at,
        notes = EXCLUDED.notes;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Helper function: revoke role from entity
CREATE OR REPLACE FUNCTION revoke_role(p_entity_id INTEGER, p_role_name VARCHAR(50))
RETURNS BOOLEAN AS $$
    DELETE FROM entity_role_assignments
    WHERE entity_id = p_entity_id
      AND role_id = (SELECT id FROM entity_roles WHERE name = p_role_name);
    SELECT TRUE;
$$ LANGUAGE SQL;

-- View: entities with their roles
CREATE OR REPLACE VIEW v_entity_roles AS
SELECT 
    e.id as entity_id,
    e.name as entity_name,
    e.type as entity_type,
    trust_level_name(e.trust_level) as trust_level,
    ARRAY_AGG(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL) as roles
FROM entities e
LEFT JOIN entity_role_assignments era ON e.id = era.entity_id 
    AND (era.expires_at IS NULL OR era.expires_at > NOW())
LEFT JOIN entity_roles r ON era.role_id = r.id
GROUP BY e.id, e.name, e.type, e.trust_level;

COMMENT ON TABLE entity_roles IS 'Role definitions for role-based access control. Roles are cumulative.';
COMMENT ON TABLE entity_role_assignments IS 'Maps entities to their assigned roles. An entity can have multiple roles.';
