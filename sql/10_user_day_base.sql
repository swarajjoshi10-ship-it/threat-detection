-- Per-entity, per-day behavioural aggregates. Entity = source user.
-- Every feature on day d uses only events from days <= d ("new host" = first seen on day d).
CREATE OR REPLACE TABLE features.user_day_base AS
WITH first_dst AS (
    SELECT src_user, dst_comp, min(day) AS first_day FROM auth_events GROUP BY ALL
), first_src AS (
    SELECT src_user, src_comp, min(day) AS first_day FROM auth_events GROUP BY ALL
), first_pair AS (
    SELECT src_user, src_comp, dst_comp, min(day) AS first_day FROM auth_events GROUP BY ALL
), first_active AS (
    SELECT src_user, min(day) AS first_day FROM auth_events GROUP BY ALL
), ev AS (
    SELECT
        a.*,
        fa.first_day AS user_first_day,
        -- On a user's first observed day everything is "new"; that is cold start, not novelty.
        (fd.first_day = a.day AND a.day > fa.first_day) AS is_new_dst,
        (fs.first_day = a.day AND a.day > fa.first_day) AS is_new_src,
        (fp.first_day = a.day AND a.day > fa.first_day) AS is_new_pair,
        a.hour IN ({{off_hours}})                       AS is_off_hours,
        (a.logon_type = 'Network' AND a.dst_comp IS DISTINCT FROM a.src_comp) AS is_remote
    FROM auth_events a
    JOIN first_active fa USING (src_user)
    LEFT JOIN first_dst fd ON fd.src_user = a.src_user AND fd.dst_comp IS NOT DISTINCT FROM a.dst_comp
    LEFT JOIN first_src fs ON fs.src_user = a.src_user AND fs.src_comp IS NOT DISTINCT FROM a.src_comp
    LEFT JOIN first_pair fp ON fp.src_user = a.src_user AND fp.src_comp IS NOT DISTINCT FROM a.src_comp
                           AND fp.dst_comp IS NOT DISTINCT FROM a.dst_comp
)
SELECT
    src_user                                                    AS entity,
    day,
    count(*)                                                    AS n_events,
    count(*) FILTER (WHERE NOT success)                         AS n_fail,
    count(DISTINCT dst_comp)                                    AS n_dst_hosts,
    count(DISTINCT src_comp)                                    AS n_src_hosts,
    count(DISTINCT dst_comp) FILTER (WHERE is_new_dst)          AS n_new_dst_hosts,
    count(DISTINCT src_comp) FILTER (WHERE is_new_src)          AS n_new_src_hosts,
    count(DISTINCT dst_comp) FILTER (WHERE is_remote)           AS n_remote_dst_hosts,
    count(*) FILTER (WHERE is_off_hours)                        AS n_off_hours,
    count(*) FILTER (WHERE auth_type = 'NTLM')                  AS n_ntlm,
    count(DISTINCT auth_type)                                   AS n_auth_types,
    count(DISTINCT logon_type)                                  AS n_logon_types,
    count(DISTINCT hour)                                        AS n_active_hours,
    -- Event-level novelty (v2, pre-registered in README "Novelty features"): count EVENTS that
    -- combine novelty with a property, instead of whole-day totals that a busy user drowns out.
    count(*) FILTER (WHERE is_new_src AND is_remote)            AS n_new_src_remote,
    count(*) FILTER (WHERE is_new_src AND auth_type = 'NTLM')   AS n_new_src_ntlm,
    count(*) FILTER (WHERE is_new_dst AND is_remote)            AS n_new_dst_remote,
    count(*) FILTER (WHERE is_new_pair)                         AS n_new_pair_events,
    any_value(day = user_first_day)                             AS is_first_day
FROM ev
GROUP BY src_user, day;
