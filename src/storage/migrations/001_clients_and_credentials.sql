-- Clients, their keys, and a record of everything this server has issued.

CREATE TABLE clients (
    client_id          TEXT PRIMARY KEY,
    subject            TEXT        NOT NULL,
    status             TEXT        NOT NULL DEFAULT 'active',
    -- NULL when the client authenticates with private_key_jwt and holds no secret.
    secret_hash        TEXT,
    auth_method        TEXT        NOT NULL DEFAULT 'client_secret_post',
    allowed_scopes     TEXT[]      NOT NULL DEFAULT '{}',
    -- Needed by token exchange: a hop may only aim a token at an audience its
    -- own client is permitted to reach.
    allowed_audiences  TEXT[]      NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT clients_status_known CHECK (status IN ('active', 'suspended'))
);

-- One row per key, so private_key_jwt can rotate without downtime. The primary
-- key is (client_id, kid): selecting on kid alone would let one client's
-- assertion be verified against another client's key.
CREATE TABLE client_keys (
    client_id  TEXT        NOT NULL REFERENCES clients (client_id) ON DELETE CASCADE,
    kid        TEXT        NOT NULL,
    public_jwk JSONB       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, kid)
);

CREATE TABLE issued_credentials (
    jti               TEXT PRIMARY KEY,
    client_id         TEXT        NOT NULL,
    subject           TEXT        NOT NULL,
    audience          TEXT        NOT NULL,
    scope             TEXT        NOT NULL DEFAULT '',
    issued_at         TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    -- Unused until phases 4 and 6, and recorded from the first issuance because
    -- they cannot be added retrospectively. A credential written today without
    -- root_subject is invisible to a revocation sweep for its whole life.
    root_subject      TEXT        NOT NULL,
    task_id           TEXT,
    delegation_depth  INTEGER     NOT NULL DEFAULT 0,
    revoked_at        TIMESTAMPTZ,
    revoked_reason    TEXT
);

CREATE INDEX issued_credentials_live_root
    ON issued_credentials (root_subject) WHERE revoked_at IS NULL;
CREATE INDEX issued_credentials_task
    ON issued_credentials (task_id) WHERE task_id IS NOT NULL;
