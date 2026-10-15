INSERT OR IGNORE INTO authority_fence(id)
SELECT ?1 WHERE NOT EXISTS (SELECT 1 FROM authority_releases WHERE id=?1)
