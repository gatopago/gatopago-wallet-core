-- A member's private vault: only what the app encrypted. The data key never arrives in the clear:
-- each passkey that can open the vault has a Mera secret vault wrapping it (`vault_keys`), and
-- each record is encrypted on the device with a key derived from it (`vault_records`).
CREATE TABLE vault_keys (
  member_id TEXT NOT NULL REFERENCES members (id),
  credential_id TEXT NOT NULL,
  vault TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (member_id, credential_id)
) STRICT;

CREATE TABLE vault_records (
  member_id TEXT NOT NULL REFERENCES members (id),
  space TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (member_id, space)
) STRICT;
