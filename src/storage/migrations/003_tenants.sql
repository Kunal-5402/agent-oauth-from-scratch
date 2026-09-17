-- Which account a client belongs to.
--
-- A tenant is never read from a request. A caller that could send a header
-- saying which account it belongs to could claim somebody else's, so the value
-- comes from the client registration and then travels inside the signature.
-- That makes cross-tenant escalation structurally impossible rather than
-- merely forbidden.
ALTER TABLE clients ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';

CREATE INDEX clients_tenant ON clients (tenant);
