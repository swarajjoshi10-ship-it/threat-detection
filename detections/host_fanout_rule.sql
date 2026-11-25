-- Host fan-out rule with a watch list. Runbook: detections/RUNBOOK.md
--
-- Reads auth_events and the hostrisk.* tables (python -m hostrisk.features --db <db>); never labels.
-- Parameters (filled by detections/rule.py, which validates their types):
--   {w}           recency window in days: a user-host pair is "recently new" for w days
--   {threshold}   fan-out that fires the rule: recent-new users / (1 + established users)
--   {min_new}     minimum recent-new users, so a host with 1 new user and 0 established can't fire
--   {watch_days}  how long a host stays on the watch list after its latest trigger
--
-- Stage 1, trigger: a source host suddenly reaches many accounts it never served before.
-- Stage 2, watch:   while a host is watched, its baseline is frozen at its first trigger. Users who
--                   first reached it from (first trigger - w) onwards stay "suspect" for as long as
--                   the watch lasts, instead of ageing into "established" after w days. This is the
--                   fix for the baseline poisoning seen on days 15-29.
-- Every value on day d uses only events from days <= d.

CREATE SCHEMA IF NOT EXISTS detections;

CREATE OR REPLACE TABLE detections.fanout_triggers AS
SELECT src_comp, day, n_recent_new_users, n_established_users, fanout
FROM hostrisk.host_day_w{w}
WHERE fanout >= {threshold} AND n_recent_new_users >= {min_new};

-- Host alerts: every day a watched host makes a remote logon, with its frozen-baseline counts.
CREATE OR REPLACE TABLE detections.fanout_host_alerts AS
WITH watched AS (
    SELECT h.src_comp, h.day, min(t.day) AS first_trigger, max(t.day) AS last_trigger
    FROM hostrisk.host_day_w{w} h
    JOIN detections.fanout_triggers t ON t.src_comp = h.src_comp AND t.day <= h.day
    GROUP BY ALL
    HAVING max(t.day) >= h.day - {watch_days}
)
SELECT
    wa.src_comp, wa.day, wa.first_trigger, wa.last_trigger,
    wa.day = wa.last_trigger                                                   AS is_trigger_day,
    count(*) FILTER (WHERE p.is_new AND p.first_day > wa.first_trigger - {w})  AS n_suspect_users,
    count(*) FILTER (WHERE NOT p.is_new OR p.first_day <= wa.first_trigger - {w}) AS n_baseline_users
FROM watched wa
JOIN hostrisk.pairs p ON p.src_comp = wa.src_comp AND p.first_day <= wa.day
GROUP BY ALL;

-- User alerts: a suspect user making a remote logon from a watched host that day.
CREATE OR REPLACE TABLE detections.fanout_user_alerts AS
WITH ud AS (
    SELECT src_user, src_comp, day, count(*) AS n_remote
    FROM auth_events
    WHERE logon_type = 'Network' AND dst_comp IS DISTINCT FROM src_comp AND src_comp IS NOT NULL
    GROUP BY ALL
)
SELECT
    ud.src_user AS entity, ud.day,
    count(DISTINCT ud.src_comp)                   AS n_watched_hosts,
    sum(ud.n_remote)                              AS n_remote_from_watched,
    arg_max(ud.src_comp, a.n_suspect_users)       AS top_host,
    min(a.first_trigger)                          AS first_trigger
FROM ud
JOIN detections.fanout_host_alerts a ON a.src_comp = ud.src_comp AND a.day = ud.day
JOIN hostrisk.pairs p ON p.src_user = ud.src_user AND p.src_comp = ud.src_comp
WHERE p.is_new AND p.first_day > a.first_trigger - {w}
GROUP BY ALL;
