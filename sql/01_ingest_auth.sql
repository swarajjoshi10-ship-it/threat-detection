-- Stream LANL-format auth.txt(.gz) into a normalized event table.
-- Grain: one row per authentication event. Clock: seconds since dataset start; day 0 = [0, 86400).
-- '?' is LANL's "unknown" marker and becomes NULL.
CREATE SCHEMA IF NOT EXISTS labels;
CREATE SCHEMA IF NOT EXISTS features;

CREATE OR REPLACE TABLE auth_events AS
WITH raw AS (
    SELECT *
    FROM read_csv(
        '{{auth_path}}',
        header = false, delim = ',', quote = '', escape = '',
        columns = {
            'time': 'BIGINT', 'src_user_domain': 'VARCHAR', 'dst_user_domain': 'VARCHAR',
            'src_comp': 'VARCHAR', 'dst_comp': 'VARCHAR', 'auth_type': 'VARCHAR',
            'logon_type': 'VARCHAR', 'orientation': 'VARCHAR', 'outcome': 'VARCHAR'
        }
    )
    WHERE time < {{max_time}}
), norm AS (
    SELECT
        time                                        AS ts,
        CAST(time // 86400 AS INTEGER)              AS day,
        CAST((time % 86400) // 3600 AS INTEGER)     AS hour,
        split_part(src_user_domain, '@', 1)         AS src_user,
        split_part(src_user_domain, '@', 2)         AS src_domain,
        split_part(dst_user_domain, '@', 1)         AS dst_user,
        NULLIF(src_comp, '?')                       AS src_comp,
        NULLIF(dst_comp, '?')                       AS dst_comp,
        NULLIF(auth_type, '?')                      AS auth_type,
        NULLIF(logon_type, '?')                     AS logon_type,
        NULLIF(orientation, '?')                    AS orientation,
        outcome = 'Success'                         AS success
    FROM raw
)
SELECT
    *,
    ends_with(src_user, '$')                        AS is_machine,
    src_user = 'ANONYMOUS LOGON'                    AS is_anonymous
FROM norm
-- Dropping machine/anonymous principals at ingest keeps the LANL subset laptop-sized.
WHERE {{include_machine_accounts}}
   OR NOT (ends_with(src_user, '$') OR src_user = 'ANONYMOUS LOGON' OR src_user = '?');
