CREATE TABLE IF NOT EXISTS websocket_frame_budgets(
    scope TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    frames INTEGER NOT NULL,
    bytes INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS websocket_frame_expiry ON websocket_frame_budgets(expires_at);
