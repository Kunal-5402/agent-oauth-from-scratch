-- Replay protection for private_key_jwt client assertions.
--
-- An assertion is single use. Without this table it is a bearer credential for
-- the whole of its exp window, and anybody who observes one can reuse it.
--
-- The primary key is (client_id, jti), never jti alone: one client must not be
-- able to deny another by claiming its jti value first.
CREATE TABLE client_assertion_jti (
    client_id  TEXT        NOT NULL,
    jti        TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, jti)
);

-- Rows are only useful until the assertion would have expired anyway.
CREATE INDEX client_assertion_jti_expiry ON client_assertion_jti (expires_at);
