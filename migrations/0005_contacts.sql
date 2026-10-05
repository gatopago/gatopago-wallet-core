-- People a member saved to pay in one tap.
CREATE TABLE contacts (
  member_id TEXT NOT NULL REFERENCES members (id),
  contact_id TEXT NOT NULL REFERENCES members (id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (member_id, contact_id)
) STRICT;

-- Invitations a member issued (`invites.issued_by`), to count who joined with them.
CREATE INDEX invites_issued_by ON invites (issued_by);
