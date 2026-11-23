-- Owner changes an account scheduled on a network (removing keys, upgrading) and that are neither
-- applied nor cancelled there yet, read from its events (`changes:<network>` cursors). The app lists
-- them in Security with "Cancel" and applies them once due.
CREATE TABLE owner_changes (
  account TEXT NOT NULL REFERENCES members (address),
  network TEXT NOT NULL,
  -- keccak256(abi.encode(sequence, call)), as the account names it: the same on every network.
  id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  call TEXT NOT NULL,
  ready_at INTEGER NOT NULL,
  -- The push telling the member, as `transfers.notify_at`: null once sent, or for the same change
  -- on another network.
  alert_at INTEGER,
  alert_attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (account, network, id)
) STRICT;
CREATE INDEX owner_changes_alert ON owner_changes (alert_at) WHERE alert_at IS NOT NULL;
