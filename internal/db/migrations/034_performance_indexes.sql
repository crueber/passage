-- +goose Up

-- Add indexes for hot-path lookups and periodic cleanup sweeps so SQLite uses
-- index searches instead of full table scans.
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials (user_id);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at
    ON mfa_challenges (expires_at);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id
    ON password_reset_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at
    ON password_reset_tokens (expires_at);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_used
    ON password_reset_tokens (used_at) WHERE used_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_magic_link_tokens_used
    ON magic_link_tokens (used_at) WHERE used_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expires_at
    ON email_verification_tokens (expires_at);

CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_used
    ON email_verification_tokens (used_at) WHERE used_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_invitations_pending_expires_at
    ON invitations (expires_at) WHERE accepted_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_invitations_pending_expires_at;
DROP INDEX IF EXISTS idx_email_verification_tokens_used;
DROP INDEX IF EXISTS idx_email_verification_tokens_expires_at;
DROP INDEX IF EXISTS idx_magic_link_tokens_used;
DROP INDEX IF EXISTS idx_password_reset_tokens_used;
DROP INDEX IF EXISTS idx_password_reset_tokens_expires_at;
DROP INDEX IF EXISTS idx_password_reset_tokens_user_id;
DROP INDEX IF EXISTS idx_mfa_challenges_expires_at;
DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;
