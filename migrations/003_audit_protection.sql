-- The audit trail is evidence, so the database refuses to change it.
-- Layer 1: these triggers reject UPDATE, DELETE and TRUNCATE for everyone,
--          including the application's own database user.
-- Layer 2: every row carries hash = sha256(prev_hash || canonical row), computed
--          in app/audit.py. Editing any old row breaks every later hash.
-- Layer 3: the chain head is published outside the database (scripts/anchor_head.py),
--          so even a superuser who disables these triggers and rebuilds the chain
--          is caught by comparing against the published head.

CREATE OR REPLACE FUNCTION tv_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (% refused)', TG_OP USING ERRCODE = '42501';
END $$;

CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION tv_audit_immutable();

CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION tv_audit_immutable();
