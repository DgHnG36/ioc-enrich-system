-- PostgreSQL Database Initialization Script for IOC Enrichment System

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS public;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- pgvector is optional in local/test environments.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Skipping optional extension "vector": %', SQLERRM;
END
$$;

-- Table: iocs
-- Stores Indicators of Compromise (IoC) data
CREATE TABLE IF NOT EXISTS iocs (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL UNIQUE,
    verdict VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'unspecified',
    source VARCHAR(255),
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    threat_context JSONB,
    metadata JSONB,
    is_active BOOLEAN NOT NULL DEFAULT true,
    detection_count INTEGER DEFAULT 0,
    
    CONSTRAINT valid_type CHECK (type IN ('unspecified', 'ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'file_path')),
    CONSTRAINT valid_verdict CHECK (verdict IN ('unspecified', 'malicious', 'suspicious', 'benign', 'unknown')),
    CONSTRAINT valid_severity CHECK (severity IN ('unspecified', 'info', 'low', 'medium', 'high', 'critical'))
);

-- Indexes for iocs table
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_verdict ON iocs(verdict);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
CREATE INDEX IF NOT EXISTS idx_iocs_is_active ON iocs(is_active);
CREATE INDEX IF NOT EXISTS idx_iocs_created_at ON iocs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_updated_at ON iocs(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_expires_at ON iocs(expires_at);
CREATE INDEX IF NOT EXISTS idx_iocs_tags ON iocs USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_iocs_threat_context ON iocs USING GIN(threat_context);
CREATE INDEX IF NOT EXISTS idx_iocs_metadata ON iocs USING GIN(metadata);

-- Table: threats
-- Stores threat intelligence data
CREATE TABLE IF NOT EXISTS threats (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'unspecified',
    description TEXT,
    threat_actors TEXT[] DEFAULT ARRAY[]::TEXT[],
    campaigns TEXT[] DEFAULT ARRAY[]::TEXT[],
    confidence FLOAT DEFAULT 0.0,
    metadata JSONB,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_threat_severity CHECK (severity IN ('unspecified', 'info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT valid_confidence CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

-- Indexes for threats table
CREATE INDEX IF NOT EXISTS idx_threats_name ON threats(name);
CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_is_active ON threats(is_active);
CREATE INDEX IF NOT EXISTS idx_threats_created_at ON threats(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_updated_at ON threats(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_threat_actors ON threats USING GIN(threat_actors);
CREATE INDEX IF NOT EXISTS idx_threats_campaigns ON threats USING GIN(campaigns);
CREATE INDEX IF NOT EXISTS idx_threats_tags ON threats USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_threats_metadata ON threats USING GIN(metadata);

-- Table: ioc_relations
-- Stores relationships between IoCs
CREATE TABLE IF NOT EXISTS ioc_relations (
    source_id VARCHAR(255) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    relation_type VARCHAR(100) NOT NULL,
    similarity_score FLOAT DEFAULT 0.0,
    source VARCHAR(255),
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    
    CONSTRAINT valid_similarity CHECK (similarity_score >= 0.0 AND similarity_score <= 1.0),
    CONSTRAINT valid_relation_type CHECK (relation_type IN ('communicates_with', 'resolves_to', 'related_to', 'dropped_by', 'uses', 'similar_to', 'duplicates', 'derived_from')),
    
    PRIMARY KEY (source_id, target_id),
    FOREIGN KEY (source_id) REFERENCES iocs(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES iocs(id) ON DELETE CASCADE
);

-- Indexes for ioc_relations table
CREATE INDEX IF NOT EXISTS idx_ioc_relations_source_id ON ioc_relations(source_id);
CREATE INDEX IF NOT EXISTS idx_ioc_relations_target_id ON ioc_relations(target_id);
CREATE INDEX IF NOT EXISTS idx_ioc_relations_relation_type ON ioc_relations(relation_type);
CREATE INDEX IF NOT EXISTS idx_ioc_relations_similarity_score ON ioc_relations(similarity_score DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_relations_source ON ioc_relations(source);
CREATE INDEX IF NOT EXISTS idx_ioc_relations_first_seen ON ioc_relations(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_relations_last_seen ON ioc_relations(last_seen DESC);

-- Table: threat_ioc_correlation
-- Maps threats to their related IoCs
CREATE TABLE IF NOT EXISTS threat_ioc_correlation (
    threat_id VARCHAR(255) NOT NULL,
    ioc_id VARCHAR(255) NOT NULL,
    source VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (threat_id, ioc_id),
    FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);

-- Indexes for threat_ioc_correlation table
CREATE INDEX IF NOT EXISTS idx_threat_ioc_correlation_threat_id ON threat_ioc_correlation(threat_id);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_correlation_ioc_id ON threat_ioc_correlation(ioc_id);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_correlation_created_at ON threat_ioc_correlation(created_at DESC);

-- Table: enrichment_cache
-- Stores cached enrichment data
CREATE TABLE IF NOT EXISTS enrichment_cache (
    id VARCHAR(255) PRIMARY KEY,
    ioc_id VARCHAR(255) NOT NULL,
    source VARCHAR(100) NOT NULL,
    enrichment_data JSONB,
    cached_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);

-- Indexes for enrichment_cache table
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_ioc_id ON enrichment_cache(ioc_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_source ON enrichment_cache(source);
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_cached_at ON enrichment_cache(cached_at DESC);
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires_at ON enrichment_cache(expires_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER trg_iocs_updated_at
BEFORE UPDATE ON iocs
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_timestamp();

CREATE TRIGGER trg_threats_updated_at
BEFORE UPDATE ON threats
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_timestamp();

CREATE TRIGGER trg_ioc_relations_updated_at
BEFORE UPDATE ON ioc_relations
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_timestamp();

-- Sample data for testing
INSERT INTO iocs (id, type, value, verdict, severity, source, description, is_active)
VALUES 
    ('ioc-001', 'ip', '192.168.1.100', 'malicious', 'high', 'test_source', 'Test IP address', true),
    ('ioc-002', 'domain', 'malware.example.com', 'malicious', 'critical', 'test_source', 'Test domain', true),
    ('ioc-003', 'hash_sha256', 'd131dd02c5e6eec4693d61c4a8e0d8', 'suspicious', 'medium', 'test_source', 'Test SHA256 hash', true)
ON CONFLICT DO NOTHING;

INSERT INTO threats (id, name, category, severity, description, is_active)
VALUES
    ('threat-001', 'Test Malware Campaign', 'malware', 'critical', 'Test threat for validation', true)
ON CONFLICT DO NOTHING;

-- Grant permissions
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
