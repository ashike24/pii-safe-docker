-- scripts/init_db.sql
-- Runs automatically on first Postgres container start.
-- SQLAlchemy creates the table via create_all(), but this sets up
-- the schema, indexes, and any seed data needed.

CREATE SCHEMA IF NOT EXISTS piisafe;

-- Audit log index for fast session queries (created by SQLAlchemy too,
-- but explicit here for documentation purposes)
-- The actual table DDL is managed by SQLAlchemy's create_all() in app/db/session.py
