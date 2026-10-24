-- TrustVault core schema.
-- Conventions:
--   * Every id is a random UUID (gen_random_uuid, built in since PG13). IDs are
--     treated as public: the defence is authorization, not unguessability.
--   * owner_id is denormalised onto grants / share_links / ai_suggestions so that
--     their row-level-security policies never reference `documents`. That keeps
--     the policies free of recursion (documents -> grants -> documents ...).
--     Triggers in 002 keep the copy correct; callers cannot choose it.

CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email               text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    full_name           text NOT NULL CHECK (length(full_name) BETWEEN 1 AND 120),
    role                text NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    password_hash       text NOT NULL,
    is_active           boolean NOT NULL DEFAULT true,
    failed_logins       integer NOT NULL DEFAULT 0,
    locked_until        timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_unique ON users (email);

-- Server-side sessions: the cookie holds a random token, the table holds only its
-- SHA-256. Deleting a row ends the session on the very next request.
CREATE TABLE sessions (
    token_hash   text PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    ip           text,
    user_agent   text
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE documents (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        uuid NOT NULL REFERENCES users(id),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    category        text NOT NULL CHECK (category IN ('HR', 'Legal', 'Finance', 'Engineering', 'Audit', 'Other')),
    current_version integer NOT NULL DEFAULT 1 CHECK (current_version >= 1),
    mime            text NOT NULL,
    size_bytes      bigint NOT NULL CHECK (size_bytes >= 0),
    deleted_at      timestamptz,
    deleted_by      uuid REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX documents_owner ON documents (owner_id);
CREATE INDEX documents_created ON documents (created_at);

-- Every version of the bytes. storage_key and wrapped_key live here, not on
-- documents, so the admin's metadata view never sees anything that could lead
-- to the content.
CREATE TABLE document_versions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    version     integer NOT NULL CHECK (version >= 1),
    filename    text NOT NULL,
    mime        text NOT NULL,
    size_bytes  bigint NOT NULL,
    sha256      text NOT NULL,
    storage_key text NOT NULL UNIQUE,
    wrapped_key bytea NOT NULL,
    created_by  uuid NOT NULL REFERENCES users(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (document_id, version)
);

CREATE TABLE grants (
    document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id),
    owner_id    uuid NOT NULL REFERENCES users(id),
    permission  text NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by  uuid NOT NULL REFERENCES users(id),
    granted_via text NOT NULL DEFAULT 'manual' CHECK (granted_via IN ('manual', 'ai_suggestion')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (document_id, user_id),
    CHECK (user_id <> owner_id)
);
CREATE INDEX grants_user ON grants (user_id);

-- External share links. Only the SHA-256 of the token is stored.
CREATE TABLE share_links (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id    uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    owner_id       uuid NOT NULL REFERENCES users(id),
    token_hash     text NOT NULL UNIQUE,
    label          text CHECK (label IS NULL OR length(label) <= 120),
    created_by     uuid NOT NULL REFERENCES users(id),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    max_downloads  integer CHECK (max_downloads IS NULL OR max_downloads BETWEEN 1 AND 1000),
    download_count integer NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    revoked_at     timestamptz,
    revoked_by     uuid REFERENCES users(id)
);

-- Encrypted file bytes when STORAGE_BACKEND=db (the default on Render's free tier,
-- whose filesystem is ephemeral). Ciphertext only; keys are in document_versions.
CREATE TABLE blobs (
    storage_key text PRIMARY KEY,
    data        bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ai_suggestions (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id          uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    owner_id             uuid NOT NULL REFERENCES users(id),
    suggested_user_id    uuid NOT NULL REFERENCES users(id),
    suggested_permission text NOT NULL DEFAULT 'read' CHECK (suggested_permission IN ('read', 'edit')),
    reason               text NOT NULL,
    source               text NOT NULL CHECK (source IN ('heuristic', 'llm')),
    status               text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    decided_by           uuid REFERENCES users(id),
    decided_at           timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now()
);

-- Append-only, hash-chained audit trail. No foreign keys on purpose: evidence
-- must outlive the purge of the document or user it describes.
CREATE TABLE audit_events (
    id             bigserial PRIMARY KEY,
    at             timestamptz NOT NULL,
    actor_id       uuid,
    actor_email    text,
    action         text NOT NULL,
    document_id    uuid,
    target_user_id uuid,
    outcome        text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    ip             text,
    user_agent     text,
    details        jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash      text NOT NULL,
    hash           text NOT NULL UNIQUE
);
CREATE INDEX audit_at ON audit_events (at);
CREATE INDEX audit_actor ON audit_events (actor_id, at);
CREATE INDEX audit_document ON audit_events (document_id, at);
CREATE INDEX audit_action ON audit_events (action, at);
