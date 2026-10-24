-- Lock B: the database refuses to return or change rows the current user was
-- not granted, independently of the application's own authorize() check.
--
-- The application sets these transaction-local settings at the start of every
-- transaction (app/db.py):
--   app.user_id          uuid of the signed-in user, '' if anonymous
--   app.role             'admin' | 'owner' | 'viewer' | ''
--   app.share_token_hash sha256 of a presented share-link token, '' otherwise
--   app.system           'on' only in migrations, seed, purge and ownership transfer
--
-- FORCE ROW LEVEL SECURITY is essential: on Render (and most hosts) the app
-- connects as the table owner, and without FORCE the owner silently bypasses RLS.

CREATE OR REPLACE FUNCTION tv_uid() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION tv_role() RETURNS text LANGUAGE sql STABLE AS
$$ SELECT coalesce(nullif(current_setting('app.role', true), ''), 'none') $$;

CREATE OR REPLACE FUNCTION tv_share() RETURNS text LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.share_token_hash', true), '') $$;

CREATE OR REPLACE FUNCTION tv_system() RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT coalesce(current_setting('app.system', true), '') = 'on' $$;

-- Does the current user hold a grant (of at least `min_perm`) on this document?
CREATE OR REPLACE FUNCTION tv_has_grant(doc uuid, min_perm text) RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT EXISTS (
       SELECT 1 FROM grants g
        WHERE g.document_id = doc
          AND g.user_id = tv_uid()
          AND (min_perm = 'read' OR g.permission = 'edit')) $$;

-- Does the presented share token currently open this document?
CREATE OR REPLACE FUNCTION tv_share_allows(doc uuid) RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT EXISTS (
       SELECT 1 FROM share_links s
        WHERE s.document_id = doc
          AND s.token_hash = tv_share()
          AND s.revoked_at IS NULL
          AND s.expires_at > now()
          AND (s.max_downloads IS NULL OR s.download_count < s.max_downloads)) $$;

-- ---------------------------------------------------------------- documents
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- Owners see their own rows (including their trash). Everyone else needs a live
-- document plus a grant or a working share token. Admins see metadata rows only;
-- the content path (document_versions, blobs) excludes them below.
CREATE POLICY documents_select ON documents FOR SELECT USING (
    tv_system()
    OR owner_id = tv_uid()
    OR (deleted_at IS NULL AND (
            tv_role() = 'admin'
            OR tv_has_grant(id, 'read')
            OR tv_share_allows(id)))
);

CREATE POLICY documents_insert ON documents FOR INSERT WITH CHECK (
    tv_system() OR (owner_id = tv_uid() AND tv_role() = 'owner')
);

CREATE POLICY documents_update ON documents FOR UPDATE
    USING (tv_system() OR owner_id = tv_uid() OR (deleted_at IS NULL AND tv_has_grant(id, 'edit')))
    WITH CHECK (tv_system() OR owner_id = tv_uid() OR tv_has_grant(id, 'edit'));

CREATE POLICY documents_delete ON documents FOR DELETE USING (tv_system());

-- Column-level rules an RLS policy cannot express (it cannot compare OLD/NEW).
CREATE OR REPLACE FUNCTION tv_documents_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF tv_system() THEN
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'immutable document column' USING ERRCODE = '42501';
    END IF;
    IF NEW.owner_id <> OLD.owner_id THEN
        RAISE EXCEPTION 'ownership can only change through an admin transfer' USING ERRCODE = '42501';
    END IF;
    IF OLD.owner_id IS DISTINCT FROM tv_uid()
       AND (NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR NEW.deleted_by IS DISTINCT FROM OLD.deleted_by) THEN
        RAISE EXCEPTION 'only the owner may delete or restore' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER documents_guard BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION tv_documents_guard();

-- ------------------------------------------- owner_id copy for child tables
CREATE OR REPLACE FUNCTION tv_fill_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    o   uuid;
    del timestamptz;
BEGIN
    -- Runs as the caller, so this SELECT is itself subject to documents RLS:
    -- a caller who cannot see the document gets NULL and is refused.
    SELECT d.owner_id, d.deleted_at INTO o, del FROM documents d WHERE d.id = NEW.document_id;
    IF o IS NULL THEN
        RAISE EXCEPTION 'document not found' USING ERRCODE = '42501';
    END IF;
    IF del IS NOT NULL AND NOT tv_system() THEN
        RAISE EXCEPTION 'document is deleted' USING ERRCODE = '42501';
    END IF;
    -- Nested IF: plpgsql resolves NEW.user_id when the expression runs, and only
    -- the grants table has that column.
    IF TG_TABLE_NAME = 'grants' THEN
        IF (TG_OP = 'INSERT' OR NEW.user_id <> OLD.user_id)
           AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_active) THEN
            RAISE EXCEPTION 'grantee is not an active user' USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.owner_id := o;
    RETURN NEW;
END $$;

-- ------------------------------------------------------------------ grants
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants FORCE ROW LEVEL SECURITY;

CREATE TRIGGER grants_fill_owner BEFORE INSERT OR UPDATE ON grants
    FOR EACH ROW EXECUTE FUNCTION tv_fill_owner();

-- A grantee sees their own grant row; the owner sees all grants on their documents.
CREATE POLICY grants_select ON grants FOR SELECT USING (
    tv_system() OR user_id = tv_uid() OR owner_id = tv_uid() OR tv_role() = 'admin'
);
-- Only the real owner can grant, change or revoke (editors cannot share onward).
CREATE POLICY grants_insert ON grants FOR INSERT WITH CHECK (tv_system() OR owner_id = tv_uid());
CREATE POLICY grants_update ON grants FOR UPDATE
    USING (tv_system() OR owner_id = tv_uid()) WITH CHECK (tv_system() OR owner_id = tv_uid());
CREATE POLICY grants_delete ON grants FOR DELETE USING (tv_system() OR owner_id = tv_uid());

-- ------------------------------------------------------------- share_links
ALTER TABLE share_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_links FORCE ROW LEVEL SECURITY;

CREATE TRIGGER share_links_fill_owner BEFORE INSERT ON share_links
    FOR EACH ROW EXECUTE FUNCTION tv_fill_owner();

CREATE POLICY share_links_select ON share_links FOR SELECT USING (
    tv_system() OR owner_id = tv_uid() OR token_hash = tv_share() OR tv_role() = 'admin'
);
CREATE POLICY share_links_insert ON share_links FOR INSERT WITH CHECK (tv_system() OR owner_id = tv_uid());
CREATE POLICY share_links_update ON share_links FOR UPDATE
    USING (tv_system() OR owner_id = tv_uid() OR token_hash = tv_share())
    WITH CHECK (tv_system() OR owner_id = tv_uid() OR token_hash = tv_share());
CREATE POLICY share_links_delete ON share_links FOR DELETE USING (tv_system());

-- An owner may only revoke; an anonymous token holder may only add one to the
-- download counter. Nobody may extend an expiry, un-revoke, or swap the token.
CREATE OR REPLACE FUNCTION tv_share_links_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF tv_system() THEN
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.document_id <> OLD.document_id OR NEW.owner_id <> OLD.owner_id
       OR NEW.token_hash <> OLD.token_hash OR NEW.expires_at <> OLD.expires_at
       OR NEW.max_downloads IS DISTINCT FROM OLD.max_downloads OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'share link fields are immutable' USING ERRCODE = '42501';
    END IF;
    IF OLD.owner_id = tv_uid() THEN
        IF NEW.download_count <> OLD.download_count THEN
            RAISE EXCEPTION 'owner cannot change the download counter' USING ERRCODE = '42501';
        END IF;
        IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
            RAISE EXCEPTION 'a revoked link stays revoked' USING ERRCODE = '42501';
        END IF;
    ELSE
        IF NEW.download_count <> OLD.download_count + 1
           OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
           OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by THEN
            RAISE EXCEPTION 'token holder may only record one download' USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER share_links_guard BEFORE UPDATE ON share_links
    FOR EACH ROW EXECUTE FUNCTION tv_share_links_guard();

-- ------------------------------------------------------- document_versions
ALTER TABLE document_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_versions FORCE ROW LEVEL SECURITY;

-- The content path. Deliberately has NO admin clause: an administrator can see
-- that a document exists, never its storage key or wrapped data key. Content of a
-- document in the trash is unreachable even for its owner until it is restored.
CREATE POLICY versions_select ON document_versions FOR SELECT USING (
    tv_system()
    OR EXISTS (
        SELECT 1 FROM documents d
         WHERE d.id = document_versions.document_id
           AND d.deleted_at IS NULL
           AND (d.owner_id = tv_uid() OR tv_has_grant(d.id, 'read') OR tv_share_allows(d.id)))
);
CREATE POLICY versions_insert ON document_versions FOR INSERT WITH CHECK (
    tv_system()
    OR (created_by = tv_uid() AND EXISTS (
            SELECT 1 FROM documents d
             WHERE d.id = document_versions.document_id
               AND d.deleted_at IS NULL
               AND (d.owner_id = tv_uid() OR tv_has_grant(d.id, 'edit'))))
);
CREATE POLICY versions_delete ON document_versions FOR DELETE USING (tv_system());
-- No UPDATE policy: versions are immutable once written.

-- ------------------------------------------------------------------- blobs
ALTER TABLE blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE blobs FORCE ROW LEVEL SECURITY;

-- Chained: a blob is visible only if a version row pointing at it is visible.
CREATE POLICY blobs_select ON blobs FOR SELECT USING (
    tv_system() OR EXISTS (SELECT 1 FROM document_versions v WHERE v.storage_key = blobs.storage_key)
);
CREATE POLICY blobs_insert ON blobs FOR INSERT WITH CHECK (tv_system() OR tv_uid() IS NOT NULL);
CREATE POLICY blobs_delete ON blobs FOR DELETE USING (tv_system());

-- ----------------------------------------------------------- ai_suggestions
ALTER TABLE ai_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_suggestions FORCE ROW LEVEL SECURITY;

CREATE TRIGGER ai_suggestions_fill_owner BEFORE INSERT ON ai_suggestions
    FOR EACH ROW EXECUTE FUNCTION tv_fill_owner();

CREATE POLICY ai_select ON ai_suggestions FOR SELECT USING (tv_system() OR owner_id = tv_uid());
CREATE POLICY ai_insert ON ai_suggestions FOR INSERT WITH CHECK (tv_system() OR owner_id = tv_uid());
CREATE POLICY ai_update ON ai_suggestions FOR UPDATE
    USING (tv_system() OR owner_id = tv_uid()) WITH CHECK (tv_system() OR owner_id = tv_uid());
CREATE POLICY ai_delete ON ai_suggestions FOR DELETE USING (tv_system());
