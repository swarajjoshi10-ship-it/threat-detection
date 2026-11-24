-- Red-team ground truth. Lives in the `labels` schema and is used ONLY for evaluation;
-- nothing under `features` may read from here (enforced by tests/test_features.py).
CREATE OR REPLACE TABLE labels.redteam_events AS
SELECT
    time                                    AS ts,
    CAST(time // 86400 AS INTEGER)          AS day,
    split_part(user_domain, '@', 1)         AS src_user,
    src_comp,
    dst_comp
FROM read_csv(
    '{{redteam_path}}',
    header = false, delim = ',', quote = '', escape = '',
    columns = {'time': 'BIGINT', 'user_domain': 'VARCHAR', 'src_comp': 'VARCHAR', 'dst_comp': 'VARCHAR'}
)
WHERE time < {{max_time}};

-- Event-level match: how many red-team rows can be found in the ingested auth stream.
-- A low match rate signals a parsing/filtering bug or label noise; it is reported, not hidden.
CREATE OR REPLACE TABLE labels.redteam_match AS
SELECT
    r.*,
    EXISTS (
        SELECT 1 FROM auth_events a
        WHERE a.ts = r.ts AND a.src_user = r.src_user
          AND a.src_comp = r.src_comp AND a.dst_comp = r.dst_comp
    ) AS matched_in_auth
FROM labels.redteam_events r;

-- Evaluation unit: (entity, day). Built from the red-team file directly, not via the join,
-- so an unmatched red-team row still marks its entity-day as malicious.
CREATE OR REPLACE TABLE labels.user_day AS
SELECT src_user AS entity, day, count(*) AS n_redteam_events, TRUE AS is_malicious
FROM labels.redteam_events
GROUP BY ALL;
