WITH limits(scope, frame_limit, byte_limit) AS (
    VALUES (?1, 240, 8388608), (?2, 480, 16777216), ('room', 4096, 134217728)
)
INSERT INTO websocket_frame_budgets(scope, expires_at, frames, bytes)
SELECT scope, ?3 + 10000, 1, ?4 FROM limits
WHERE (SELECT COUNT(*) FROM websocket_frame_budgets)
    + (SELECT COUNT(*) FROM limits l WHERE NOT EXISTS (
        SELECT 1 FROM websocket_frame_budgets b WHERE b.scope=l.scope
    )) <= 1024
AND NOT EXISTS (
    SELECT 1 FROM limits l LEFT JOIN websocket_frame_budgets b ON b.scope=l.scope
    WHERE COALESCE(b.frames,0) >= l.frame_limit
       OR COALESCE(b.bytes,0) + ?4 > l.byte_limit
)
ON CONFLICT(scope) DO UPDATE SET
    frames=websocket_frame_budgets.frames+1,
    bytes=websocket_frame_budgets.bytes+excluded.bytes
RETURNING scope;
