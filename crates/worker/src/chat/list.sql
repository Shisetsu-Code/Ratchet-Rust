WITH visible AS (
 SELECT c.chat_id,c.workspace_id,c.created_at,c.owner_admin_user_id,
 COALESCE(s.revision,0) AS revision,r.message_revision,r.receipt_revision,r.mutation_revision,r.device_revision,
 (SELECT m.user_id FROM active_chat_members m WHERE m.chat_id=c.chat_id AND m.participant_role='CUSTOMER' ORDER BY m.joined_at,m.user_id LIMIT 1) AS customer_user_id,
 COALESCE((SELECT i.created_by_user_id FROM invitation_claims x JOIN invitations i ON i.invitation_id=x.invitation_id WHERE x.chat_id=c.chat_id ORDER BY x.claimed_at LIMIT 1),
 (SELECT i.created_by_user_id FROM invitations i WHERE i.chat_id=c.chat_id ORDER BY i.created_at LIMIT 1)) AS referred_by_user_id
 FROM chats c JOIN chat_revisions r ON r.chat_id=c.chat_id
 LEFT JOIN chat_storage_stats s ON s.chat_id=c.chat_id
 JOIN active_chat_members m ON m.chat_id=c.chat_id AND m.user_id=?1
)
SELECT visible.*,
 CASE WHEN visible.customer_user_id IS NULL THEN NULL WHEN EXISTS(SELECT 1 FROM customer_accounts ca WHERE ca.user_id=visible.customer_user_id) THEN 1 ELSE 0 END AS customer_has_account,
 issuer.display_name AS referred_by_display_name,issuer.staff_role AS referred_by_staff_role,
 (SELECT s.display_name FROM workspace_staff s WHERE s.workspace_id=visible.workspace_id AND s.user_id=visible.owner_admin_user_id AND s.staff_role IN ('ADMIN','OWNER') AND s.revoked_at IS NULL LIMIT 1) AS support_display_name,
 contact.display_name AS customer_display_name
FROM visible
LEFT JOIN workspace_staff issuer ON issuer.workspace_id=visible.workspace_id AND issuer.user_id=visible.referred_by_user_id
LEFT JOIN customer_contacts contact ON contact.workspace_id=visible.workspace_id AND contact.user_id=visible.customer_user_id
ORDER BY visible.created_at DESC
