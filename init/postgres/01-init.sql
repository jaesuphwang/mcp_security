-- Initialize MCP Security Guardian PostgreSQL database

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS detection;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS revocation;
CREATE SCHEMA IF NOT EXISTS audit;

-- Create role for application
-- (Should already exist from Docker Compose environment variables)
-- CREATE ROLE mcp_security WITH LOGIN PASSWORD 'password';

-- Grant privileges
GRANT ALL PRIVILEGES ON SCHEMA public TO mcp_security;
GRANT ALL PRIVILEGES ON SCHEMA detection TO mcp_security;
GRANT ALL PRIVILEGES ON SCHEMA security TO mcp_security;
GRANT ALL PRIVILEGES ON SCHEMA revocation TO mcp_security;
GRANT ALL PRIVILEGES ON SCHEMA audit TO mcp_security;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    user_id TEXT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details JSONB,
    ip_address TEXT,
    user_agent TEXT
);

-- Create indexes for audit log
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON audit.logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_user_id ON audit.logs (user_id);
CREATE INDEX IF NOT EXISTS idx_logs_action ON audit.logs (action);
CREATE INDEX IF NOT EXISTS idx_logs_entity_type_id ON audit.logs (entity_type, entity_id);

-- Create API keys table
CREATE TABLE IF NOT EXISTS security.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Create indexes for API keys
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON security.api_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_organization_id ON security.api_keys (organization_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON security.api_keys (is_active);

-- Create token revocation table
CREATE TABLE IF NOT EXISTS revocation.token_revocations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_id TEXT NOT NULL UNIQUE,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    details JSONB
);

-- Create indexes for token revocations
CREATE INDEX IF NOT EXISTS idx_token_revocations_token_id ON revocation.token_revocations (token_id);
CREATE INDEX IF NOT EXISTS idx_token_revocations_revoked_at ON revocation.token_revocations (revoked_at);
CREATE INDEX IF NOT EXISTS idx_token_revocations_expires_at ON revocation.token_revocations (expires_at);

-- Create threat patterns table
CREATE TABLE IF NOT EXISTS detection.threat_patterns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    pattern_type TEXT NOT NULL,
    pattern_value TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    false_positive_rate FLOAT DEFAULT 0.0,
    metadata JSONB
);

-- Create indexes for threat patterns
CREATE INDEX IF NOT EXISTS idx_threat_patterns_pattern_type ON detection.threat_patterns (pattern_type);
CREATE INDEX IF NOT EXISTS idx_threat_patterns_severity ON detection.threat_patterns (severity);
CREATE INDEX IF NOT EXISTS idx_threat_patterns_is_enabled ON detection.threat_patterns (is_enabled);
CREATE INDEX IF NOT EXISTS idx_threat_patterns_name_trgm ON detection.threat_patterns USING GIN (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_threat_patterns_pattern_value_trgm ON detection.threat_patterns USING GIN (pattern_value gin_trgm_ops);

-- Create detection events table
CREATE TABLE IF NOT EXISTS detection.events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    session_id TEXT,
    instruction TEXT NOT NULL,
    is_threat BOOLEAN NOT NULL,
    confidence FLOAT NOT NULL,
    risk_level TEXT NOT NULL,
    threat_type TEXT,
    matched_patterns JSONB,
    analysis_time_ms INTEGER,
    user_id TEXT,
    organization_id TEXT,
    source_ip TEXT,
    details JSONB
);

-- Create indexes for detection events
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON detection.events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_is_threat ON detection.events (is_threat);
CREATE INDEX IF NOT EXISTS idx_events_risk_level ON detection.events (risk_level);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON detection.events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_user_id ON detection.events (user_id);
CREATE INDEX IF NOT EXISTS idx_events_organization_id ON detection.events (organization_id);

-- Create vulnerability scans table
CREATE TABLE IF NOT EXISTS detection.vulnerability_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target TEXT NOT NULL,
    scan_types TEXT[] NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL,
    scan_duration_ms INTEGER,
    findings_count INTEGER DEFAULT 0,
    risk_assessment JSONB,
    user_id TEXT,
    organization_id TEXT,
    details JSONB
);

-- Create indexes for vulnerability scans
CREATE INDEX IF NOT EXISTS idx_vulnerability_scans_timestamp ON detection.vulnerability_scans (timestamp);
CREATE INDEX IF NOT EXISTS idx_vulnerability_scans_target ON detection.vulnerability_scans (target);
CREATE INDEX IF NOT EXISTS idx_vulnerability_scans_status ON detection.vulnerability_scans (status);
CREATE INDEX IF NOT EXISTS idx_vulnerability_scans_user_id ON detection.vulnerability_scans (user_id);
CREATE INDEX IF NOT EXISTS idx_vulnerability_scans_organization_id ON detection.vulnerability_scans (organization_id);

-- Create vulnerability findings table
CREATE TABLE IF NOT EXISTS detection.vulnerability_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES detection.vulnerability_scans(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    affected_component TEXT,
    fix_recommendation TEXT,
    details JSONB,
    UNIQUE(scan_id, title)
);

-- Create indexes for vulnerability findings
CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_scan_id ON detection.vulnerability_findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_severity ON detection.vulnerability_findings (severity);
CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_finding_type ON detection.vulnerability_findings (finding_type);

-- Create users table for authentication (minimal version, can be extended)
CREATE TABLE IF NOT EXISTS security.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    organization_id TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    metadata JSONB
);

-- Create indexes for users
CREATE INDEX IF NOT EXISTS idx_users_email ON security.users (email);
CREATE INDEX IF NOT EXISTS idx_users_organization_id ON security.users (organization_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON security.users (role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON security.users (is_active);

-- Create function to update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update updated_at timestamp for threat patterns
CREATE TRIGGER update_threat_patterns_updated_at
BEFORE UPDATE ON detection.threat_patterns
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Admin user creation must be done through the application setup
-- Run the following command after deployment:
-- docker-compose exec api python -m src.scripts.create_admin_user
-- This ensures secure password generation and proper setup

-- Grant privileges to sequences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_security;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA detection TO mcp_security;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA security TO mcp_security;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA revocation TO mcp_security;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO mcp_security; 