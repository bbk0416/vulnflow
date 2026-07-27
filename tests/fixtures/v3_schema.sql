
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    product_version TEXT,
    asset_id TEXT,
    asset_name TEXT,
    environment TEXT,
    cve_id TEXT NOT NULL,
    component TEXT,
    component_version TEXT,
    cvss REAL DEFAULT 0,
    epss REAL DEFAULT 0,
    epss_percentile REAL DEFAULT 0,
    kev INTEGER DEFAULT 0,
    internet_exposed INTEGER DEFAULT 0,
    asset_criticality INTEGER DEFAULT 1,
    data_sensitivity INTEGER DEFAULT 1,
    patch_available INTEGER DEFAULT 0,
    compensating_control INTEGER DEFAULT 0,
    status TEXT DEFAULT 'OPEN',
    owner TEXT,
    due_date TEXT,
    exception_expiry TEXT,
    risk_acceptance_reason TEXT,
    risk_acceptance_approver TEXT,
    notes TEXT,
    intel_source TEXT DEFAULT 'manual',
    intel_updated_at TEXT,
    score INTEGER DEFAULT 0,
    threat_score INTEGER DEFAULT 0,
    asset_context_score INTEGER DEFAULT 0,
    remediation_urgency_score INTEGER DEFAULT 0,
    decision TEXT,
    decision_label TEXT,
    sla_days INTEGER,
    target_date TEXT,
    mitigation_required INTEGER DEFAULT 0,
    reasons TEXT,
    policy_version TEXT,
    first_seen_at TEXT,
    first_scored_at TEXT,
    last_scored_at TEXT,
    resolved_at TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT,
    event_type TEXT NOT NULL,
    actor TEXT DEFAULT 'local-user',
    summary TEXT NOT NULL,
    details_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_decision ON findings(decision);
CREATE INDEX IF NOT EXISTS idx_audit_finding ON audit_events(finding_id, created_at DESC);
