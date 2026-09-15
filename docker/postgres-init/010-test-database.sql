-- The suite runs against its own database, so a local poke at the development
-- one can never make a test pass or fail.
CREATE DATABASE oauth_test OWNER oauth;
