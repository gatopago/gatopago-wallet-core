-- Invitations are operator-defined text, not generated bearer-token hashes.
-- Hashes cannot be reversed. Stop if old invitations exist instead of silently
-- discarding their history or treating a hash as a usable invitation code.
CREATE TABLE _invitation_codes_guard (
  old_invitation_count INTEGER NOT NULL CHECK (old_invitation_count = 0)
) STRICT;
INSERT INTO _invitation_codes_guard SELECT COUNT(*) FROM signup_invites;
DROP TABLE _invitation_codes_guard;

ALTER TABLE auth_challenges RENAME TO _auth_challenges_hashed;
ALTER TABLE signup_invites RENAME TO _signup_invites_hashed;

CREATE TABLE signup_invites (
  code TEXT PRIMARY KEY NOT NULL CHECK (code <> ''),
  issued_by TEXT NOT NULL CHECK (length(issued_by) BETWEEN 1 AND 128),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  revoked_at INTEGER,
  consumed_by TEXT UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  consumed_at INTEGER,
  CHECK ((consumed_by IS NULL AND consumed_at IS NULL) OR
    (consumed_by IS NOT NULL AND consumed_at >= created_at AND consumed_at < expires_at))
) STRICT;

CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'op_*'),
  purpose TEXT NOT NULL CHECK (purpose IN ('register','login')),
  challenge TEXT NOT NULL UNIQUE CHECK (length(challenge) = 66),
  proof_challenge TEXT UNIQUE,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  proposed_user_id TEXT UNIQUE,
  invite_code TEXT REFERENCES signup_invites(code) ON DELETE RESTRICT,
  display_name TEXT,
  username TEXT,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at = created_at + 300),
  consumed_at INTEGER CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at < expires_at)),
  CHECK ((purpose = 'login' AND proof_challenge IS NULL AND proposed_user_id IS NULL
    AND invite_code IS NULL AND display_name IS NULL AND username IS NULL)
    OR (purpose = 'register' AND proof_challenge IS NOT NULL AND proposed_user_id IS NOT NULL
      AND invite_code IS NOT NULL AND length(display_name) BETWEEN 1 AND 80
      AND username IS NOT NULL AND length(username) BETWEEN 5 AND 30
      AND length(proof_challenge) = 66 AND length(proposed_user_id) = 40))
) STRICT;

-- Existing login challenges and all users/credentials remain unchanged.
INSERT INTO auth_challenges
  (id,purpose,challenge,proof_challenge,rp_id,origin,proposed_user_id,invite_code,display_name,username,created_at,expires_at,consumed_at)
SELECT id,purpose,challenge,proof_challenge,rp_id,origin,proposed_user_id,invite_hash,display_name,username,created_at,expires_at,consumed_at
FROM _auth_challenges_hashed;

DROP TABLE _auth_challenges_hashed;
DROP TABLE _signup_invites_hashed;

CREATE INDEX auth_challenges_expiry ON auth_challenges(expires_at);
CREATE INDEX auth_challenges_invite ON auth_challenges(invite_code) WHERE invite_code IS NOT NULL;
CREATE INDEX signup_invites_expiry ON signup_invites(consumed_by, expires_at) WHERE consumed_by IS NULL;
