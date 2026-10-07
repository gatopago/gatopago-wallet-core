-- Ed25519 keys that also sign for members' Stellar accounts: the keys Mera derives from a passkey.
-- An owner key of the EVM account approves each one (`stellarKeyApproval`), and it counts only
-- while that owner still owns the account. Losing a row means approving the key again.
CREATE TABLE stellar_keys (
  member_address TEXT NOT NULL REFERENCES members (address),
  public_key TEXT NOT NULL,
  owner TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (member_address, public_key)
) STRICT;
