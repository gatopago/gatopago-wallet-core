-- Sign-ins to GatoPago Business approved from the app: the console shows `id` as a QR, a signed-in
-- member approves it with their passkey, and only the console, holding the secret, collects the
-- session. Each request lasts a couple of minutes and is collected once.
CREATE TABLE business_logins (
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  -- What the member sees before approving: the console's browser and approximate place.
  device TEXT NOT NULL,
  place TEXT,
  expires_at INTEGER NOT NULL,
  member_id TEXT REFERENCES members (id),
  address TEXT,
  collected INTEGER NOT NULL DEFAULT 0
) STRICT;
