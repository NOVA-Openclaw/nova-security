-- Trust Levels Schema
-- Formalizes the existing entities.trust_level integer into named tiers

-- Trust level reference table
CREATE TABLE IF NOT EXISTS trust_levels (
    level INTEGER PRIMARY KEY,
    name VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    can_communicate BOOLEAN DEFAULT FALSE,
    can_request_actions BOOLEAN DEFAULT FALSE
);

-- Insert standard trust levels
INSERT INTO trust_levels (level, name, description, can_communicate, can_request_actions) VALUES
    (0, 'untrusted', 'Unknown entity, no interaction permitted', FALSE, FALSE),
    (1, 'known', 'Identified but unverified, listen-only', FALSE, FALSE),
    (2, 'verified', 'Identity confirmed, limited interaction', TRUE, FALSE),
    (3, 'trusted', 'Full interaction, standard permissions', TRUE, FALSE),
    (4, 'privileged', 'Extended permissions, can request sensitive actions', TRUE, TRUE),
    (5, 'admin', 'Full administrative access', TRUE, TRUE)
ON CONFLICT (level) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    can_communicate = EXCLUDED.can_communicate,
    can_request_actions = EXCLUDED.can_request_actions;

-- Helper function: get trust level name
CREATE OR REPLACE FUNCTION trust_level_name(p_level INTEGER) 
RETURNS VARCHAR(20) AS $$
    SELECT name FROM trust_levels WHERE level = p_level;
$$ LANGUAGE SQL STABLE;

-- Helper function: get trust level details
CREATE OR REPLACE FUNCTION trust_level_info(p_level INTEGER) 
RETURNS TABLE(name VARCHAR(20), description TEXT, can_communicate BOOLEAN, can_request_actions BOOLEAN) AS $$
    SELECT name, description, can_communicate, can_request_actions 
    FROM trust_levels WHERE level = p_level;
$$ LANGUAGE SQL STABLE;

-- Add constraint to entities table if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'entities_trust_level_check'
    ) THEN
        ALTER TABLE entities ADD CONSTRAINT entities_trust_level_check 
            CHECK (trust_level >= 0 AND trust_level <= 5);
    END IF;
END $$;

-- Ensure default trust level is 0 (deny by default)
ALTER TABLE entities ALTER COLUMN trust_level SET DEFAULT 0;

COMMENT ON TABLE trust_levels IS 'Reference table for trust level definitions. Security-sensitive.';
