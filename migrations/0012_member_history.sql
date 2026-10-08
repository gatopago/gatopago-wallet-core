-- Whether a member's history from before they joined was read (Envio HyperSync, when configured).
ALTER TABLE members ADD COLUMN history_read INTEGER NOT NULL DEFAULT 0;
