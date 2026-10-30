CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('Email', 'URL', 'HTML')),
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  classification TEXT NOT NULL CHECK (classification IN ('Low Risk', 'Suspicious', 'High Risk')),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS scans_workspace_created
  ON scans(workspace_id, created_at DESC);
