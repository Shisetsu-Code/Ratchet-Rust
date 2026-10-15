-- Guest intake and account conversion reuse the existing invitation and claim
-- records so attribution remains attached to the same chat and customer.
-- These indexes keep shared inbox and owner supervision lookups bounded.
CREATE INDEX IF NOT EXISTS idx_invitations_chat
  ON invitations(chat_id,created_at)
  WHERE chat_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_invitation_claims_chat
  ON invitation_claims(chat_id,claimed_at);
