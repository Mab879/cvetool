-- Update_operation is a table keeping a log of updater runs.
--
-- Ref is used when a specific update_operation needs to be exposed to a
-- client.
CREATE TABLE IF NOT EXISTS update_operation (
	id			INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	ref			TEXT UNIQUE NOT NULL, -- uuid ... DEFAULT uuid_generate_v4(),
	updater		TEXT NOT NULL,
	fingerprint TEXT,
	kind		TEXT,
	date		TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- TIMESTAMP WITH TIME ZONE DEFAULT now()
);
CREATE INDEX uo_updater_idx ON update_operation (updater);

-- Uo_vuln is the association table that does the many-many association
-- between update operations and vulnerabilities.
--
-- The FKs enable us to GC the vulnerabilities by first removing old
-- update_operation rows and having that cascade to this table, then
-- remove vulnerabilities that are not referenced from this table.
CREATE TABLE IF NOT EXISTS uo_vuln (
	uo   INTEGER NOT NULL,
	vuln INTEGER NOT NULL,
	PRIMARY KEY (uo, vuln),
	FOREIGN KEY (uo) REFERENCES update_operation(id) ON DELETE CASCADE,
	FOREIGN KEY (vuln) REFERENCES vuln(id) ON DELETE CASCADE
);
CREATE INDEX uo_vuln_vuln_idx ON uo_vuln (vuln);
CREATE INDEX uo_vuln_uo_idx ON uo_vuln (uo);

CREATE TABLE uo_enrich
(
    uo          INTEGER NOT NULL,
    enrich      INTEGER NOT NULL,
    updater     TEXT,
    fingerprint TEXT,
    date        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uo, enrich),
    FOREIGN KEY (uo) REFERENCES update_operation (id) ON DELETE CASCADE,
    FOREIGN KEY (enrich) REFERENCES enrichment (id) ON DELETE CASCADE
);
CREATE INDEX uo_enrich_enrich_idx ON uo_enrich (enrich);
CREATE INDEX uo_enrich_uo_idx ON uo_enrich (uo);

--
CREATE TABLE updater_status (
    updater_name TEXT PRIMARY KEY NOT NULL,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_success TIMESTAMP,
    last_run_succeeded BOOLEAN,
    last_attempt_fingerprint TEXT,
    last_error TEXT
);

-- Create view that maintains the lastest update_operation id per updater.
-- TODO: Materialized?
CREATE VIEW latest_update_operations AS
SELECT MAX(id) as id, kind, updater FROM update_operation GROUP BY updater;

CREATE INDEX enrichment_updater_idx ON enrichment (updater);
