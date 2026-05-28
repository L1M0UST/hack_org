-- PostgreSQL schema for hack_org.
-- This file mirrors the table design discussed for production storage.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS threat_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_code TEXT UNIQUE,
    canonical_name CITEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    group_type TEXT NOT NULL DEFAULT 'threat_actor',
    status TEXT NOT NULL DEFAULT 'active',
    latest_overview TEXT,
    latest_structure_overview TEXT,
    earliest_active_time DATE,
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS group_aliases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
    alias CITEXT NOT NULL,
    normalized_alias CITEXT NOT NULL,
    alias_type TEXT NOT NULL DEFAULT 'same_as',
    status TEXT NOT NULL DEFAULT 'confirmed',
    source_type TEXT NOT NULL,
    source_ref TEXT,
    confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0000,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, normalized_alias)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_group_aliases_confirmed_unique
ON group_aliases (normalized_alias)
WHERE status IN ('confirmed', 'manual_confirmed', 'auto_confirmed');

CREATE TABLE IF NOT EXISTS collected_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id TEXT NOT NULL,
    source_title TEXT,
    source_url TEXT NOT NULL,
    source_domain TEXT,
    document_type TEXT NOT NULL DEFAULT 'article',
    published_at TIMESTAMPTZ,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title TEXT,
    author TEXT,
    language TEXT,
    url_hash TEXT NOT NULL UNIQUE,
    title_hash TEXT,
    text_hash TEXT,
    raw_object_key TEXT,
    clean_object_key TEXT,
    meta_object_key TEXT,
    raw_local_path TEXT,
    clean_local_path TEXT,
    meta_local_path TEXT,
    rss_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS intel_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'A',
    category TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    weight NUMERIC(8,4) NOT NULL DEFAULT 1.0,
    fetch_full_article BOOLEAN NOT NULL DEFAULT TRUE,
    keywords JSONB NOT NULL DEFAULT '[]'::jsonb,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    api_key_env TEXT,
    auth_header TEXT,
    max_items INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
    run_type TEXT NOT NULL,
    model_name TEXT NOT NULL,
    model_version TEXT,
    prompt_version TEXT NOT NULL,
    input_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_payload JSONB,
    status TEXT NOT NULL DEFAULT 'running',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_model_runs_document_type_status
ON model_runs (document_id, run_type, status);

CREATE TABLE IF NOT EXISTS document_group_matches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES collected_documents(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
    match_confidence NUMERIC(5,4) NOT NULL,
    match_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    matched_terms JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (document_id, group_id)
);

CREATE TABLE IF NOT EXISTS group_fact_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
    fact_type TEXT NOT NULL,
    fact_value TEXT NOT NULL,
    normalized_value TEXT,
    confidence NUMERIC(5,4) NOT NULL,
    evidence_text TEXT NOT NULL,
    source_url TEXT,
    source_title TEXT,
    source_published_at TIMESTAMPTZ,
    valid_time TEXT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, document_id, fact_type, normalized_value, evidence_text)
);

CREATE TABLE IF NOT EXISTS group_structure_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
    structure_type TEXT NOT NULL,
    relation_type TEXT,
    target_entity_type TEXT,
    target_name TEXT,
    member_name TEXT,
    role TEXT,
    confidence NUMERIC(5,4) NOT NULL,
    evidence_text TEXT NOT NULL,
    source_url TEXT,
    source_title TEXT,
    source_published_at TIMESTAMPTZ,
    valid_time TEXT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_group_structure_events_dedupe
ON group_structure_events (
    group_id,
    document_id,
    structure_type,
    COALESCE(target_name, ''),
    COALESCE(member_name, ''),
    evidence_text
);

CREATE TABLE IF NOT EXISTS group_activity_timeline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
    event_id UUID,
    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
    event_date DATE,
    date_precision TEXT NOT NULL DEFAULT 'unknown',
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    targets JSONB NOT NULL DEFAULT '{}'::jsonb,
    techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
    malware JSONB NOT NULL DEFAULT '[]'::jsonb,
    vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    iocs JSONB NOT NULL DEFAULT '{}'::jsonb,
    confidence NUMERIC(5,4) NOT NULL,
    evidence_texts JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_url TEXT,
    source_title TEXT,
    source_published_at TIMESTAMPTZ,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_group_activity_timeline_dedupe
ON group_activity_timeline (
    group_id,
    document_id,
    event_type,
    title,
    COALESCE(event_date, DATE '0001-01-01')
);

CREATE TABLE IF NOT EXISTS apt_group_export (
    apt_organization TEXT PRIMARY KEY,
    organization_code TEXT,
    team_name TEXT,
    attack_type TEXT,
    technical_skills TEXT,
    suspected_source TEXT,
    affected_industry TEXT,
    alias TEXT,
    attack_pattern TEXT,
    attack_frequency TEXT,
    target_country TEXT,
    earliest_active_time TEXT,
    active_time TEXT,
    common_language TEXT,
    team_description TEXT,
    tactics TEXT,
    associated_domain TEXT,
    associative_hash TEXT,
    associative_ip TEXT,
    associative_url TEXT,
    related_certificates TEXT,
    source_evidence TEXT,
    storage_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
