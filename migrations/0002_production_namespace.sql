-- Forward-only enforcement for databases created before the single-namespace
-- baseline. Never relabel identities; stop if incompatible records exist.
CREATE TABLE _production_namespace_guard (
  incompatible_count INTEGER NOT NULL CHECK (incompatible_count = 0)
) STRICT;
INSERT INTO _production_namespace_guard
  SELECT COUNT(*) FROM users WHERE environment <> 'production';
DROP TABLE _production_namespace_guard;

CREATE TRIGGER users_production_namespace_insert
BEFORE INSERT ON users WHEN NEW.environment <> 'production'
BEGIN
  SELECT RAISE(ABORT, 'Only production identities are supported');
END;

CREATE TRIGGER users_production_namespace_update
BEFORE UPDATE OF environment ON users WHEN NEW.environment <> 'production'
BEGIN
  SELECT RAISE(ABORT, 'Only production identities are supported');
END;
