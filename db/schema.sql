-- Cypher 2.0 persistence schema
-- PostgreSQL 16+

CREATE TABLE IF NOT EXISTS sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    pcap_name       TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'replay',
    status          TEXT NOT NULL DEFAULT 'running',
    total_packets   BIGINT NOT NULL DEFAULT 0,
    total_flows     BIGINT NOT NULL DEFAULT 0,
    total_alerts    BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS flows (
    id                  BIGSERIAL PRIMARY KEY,
    session_id          UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    flow_id             BIGINT NOT NULL,
    first_ts            TIMESTAMPTZ NOT NULL,
    last_ts             TIMESTAMPTZ NOT NULL,
    src                 INET NOT NULL,
    dst                 INET NOT NULL,
    sport               INTEGER NOT NULL,
    dport               INTEGER NOT NULL,
    proto               TEXT NOT NULL,
    app                 TEXT NOT NULL DEFAULT '',
    sni                 TEXT NOT NULL DEFAULT '',
    packet_count        INTEGER NOT NULL DEFAULT 0,
    bytes               BIGINT NOT NULL DEFAULT 0,
    label               TEXT NOT NULL DEFAULT 'Unknown',
    attack_probability  NUMERIC(6, 5) NOT NULL DEFAULT 0,
    category            TEXT NOT NULL DEFAULT 'Unknown',
    is_threat           BOOLEAN NOT NULL DEFAULT false,
    is_anomaly          BOOLEAN NOT NULL DEFAULT false,
    features            JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (session_id, flow_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    flow_id         BIGINT,
    kind            TEXT NOT NULL,
    rule            TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    mitre_id        TEXT,
    mitre_name      TEXT,
    mitre_tactic    TEXT,
    src             INET,
    dst             INET,
    dport           INTEGER,
    observed_at     TIMESTAMPTZ NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    tactic      TEXT NOT NULL,
    url         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_started_at
    ON sessions (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_flows_session_dport
    ON flows (session_id, dport);

CREATE INDEX IF NOT EXISTS idx_flows_session_label
    ON flows (session_id, label);

CREATE INDEX IF NOT EXISTS idx_flows_src
    ON flows (src);

CREATE INDEX IF NOT EXISTS idx_alerts_session_time
    ON alerts (session_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_severity_time
    ON alerts (severity, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_mitre
    ON alerts (mitre_id);

CREATE INDEX IF NOT EXISTS idx_alerts_rule
    ON alerts (rule);
