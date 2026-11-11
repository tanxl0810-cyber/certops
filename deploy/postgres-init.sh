#!/bin/sh
# Only runs when the PostgreSQL data volume is empty.
(
set -eu
: "${CERTOPS_DB_PASSWORD:?Application database password is required}"
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1 <<'SQL'
\getenv app_password CERTOPS_DB_PASSWORD
SELECT format('CREATE ROLE certops LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 24', :'app_password') \gexec
CREATE DATABASE certops OWNER certops ENCODING 'UTF8';
REVOKE ALL ON DATABASE certops FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE certops TO certops;
\connect certops
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO certops;
SQL
)
