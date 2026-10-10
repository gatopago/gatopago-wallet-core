-- Keys GatoPago Business signs in with: an Ed25519 key each passkey derives in its own PRF namespace
-- (`businessKey` in @gatopago/shared/passkey), bound to the account by an owner's approval in the
-- app. A sign-in credential only: no account, on EVM or Stellar, has it as a signer. It counts while
-- the owner that approved it owns the account; deleting it ends the sessions it opened.
CREATE TABLE business_keys (
  public_key TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members (id),
  owner TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX business_keys_member ON business_keys (member_id);

-- The key a console asks to bind with its sign-in QR, if any.
ALTER TABLE business_logins ADD COLUMN public_key TEXT;
