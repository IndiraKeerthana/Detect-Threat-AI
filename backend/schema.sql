-- Supabase PostgreSQL Schema Initialization for DetectThreatAI Completed Cases

CREATE TABLE IF NOT EXISTS completed_cases (
    id VARCHAR(128) PRIMARY KEY,
    title VARCHAR(512) NOT NULL,
    subject VARCHAR(512) NOT NULL,
    sender VARCHAR(256) NOT NULL,
    recipient VARCHAR(256) NOT NULL,
    severity VARCHAR(64) NOT NULL,
    classification VARCHAR(64) NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence VARCHAR(64) NOT NULL,
    status VARCHAR(64) NOT NULL,
    created_at VARCHAR(128) NOT NULL,
    updated_at VARCHAR(128) NOT NULL,
    source_ip VARCHAR(128) NOT NULL,
    analyst_notes TEXT,
    investigation_data JSONB NOT NULL
);

-- Performance Indexes for search and filtering
CREATE INDEX IF NOT EXISTS idx_completed_cases_subject ON completed_cases (subject);
CREATE INDEX IF NOT EXISTS idx_completed_cases_sender ON completed_cases (sender);
CREATE INDEX IF NOT EXISTS idx_completed_cases_classification ON completed_cases (classification);
CREATE INDEX IF NOT EXISTS idx_completed_cases_status ON completed_cases (status);
CREATE INDEX IF NOT EXISTS idx_completed_cases_created_at ON completed_cases (created_at DESC);
