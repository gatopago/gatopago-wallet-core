-- Devices that receive a member's payment notifications (Firebase Cloud Messaging tokens).
CREATE TABLE push_tokens (
  token TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members (id),
  language TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX push_tokens_member ON push_tokens (member_id);
