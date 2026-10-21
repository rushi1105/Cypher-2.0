-- Real analytical queries used by the dashboard/reporting layer.

-- 1. Alerts by severity over time (5-minute buckets).
SELECT
    date_trunc('hour', observed_at)
        + INTERVAL '5 minutes' * floor(extract(minute FROM observed_at) / 5) AS bucket,
    severity,
    count(*) AS alerts
FROM alerts
WHERE session_id = $1
GROUP BY bucket, severity
ORDER BY bucket, severity;

-- 2. Top talkers per session by bytes and packets.
SELECT
    src,
    count(*) AS flows,
    sum(packet_count) AS packets,
    sum(bytes) AS bytes,
    max(attack_probability) AS max_attack_probability
FROM flows
WHERE session_id = $1
GROUP BY src
ORDER BY bytes DESC
LIMIT 20;

-- 3. Top destination ports per session.
SELECT
    dport,
    count(*) AS flows,
    sum(packet_count) AS packets,
    count(*) FILTER (WHERE is_threat) AS threat_flows
FROM flows
WHERE session_id = $1
GROUP BY dport
ORDER BY threat_flows DESC, packets DESC
LIMIT 20;

-- 4. MITRE technique counts per session.
SELECT
    mitre_id,
    mitre_name,
    mitre_tactic,
    count(*) AS alerts
FROM alerts
WHERE session_id = $1 AND mitre_id IS NOT NULL
GROUP BY mitre_id, mitre_name, mitre_tactic
ORDER BY alerts DESC;

-- 5. Latest critical/high alerts.
SELECT
    observed_at,
    severity,
    rule,
    title,
    src,
    dst,
    dport,
    mitre_id
FROM alerts
WHERE session_id = $1 AND severity IN ('critical', 'high')
ORDER BY observed_at DESC
LIMIT 50;
