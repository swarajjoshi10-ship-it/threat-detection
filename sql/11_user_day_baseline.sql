-- Dense entity x day grid (inactive days are real zeros, not missing) + rolling baselines.
-- Baseline window = the previous {{window}} calendar days, EXCLUDING day d itself, so today's
-- behaviour never contaminates its own baseline. z-scores are NULL until the entity has
-- {{min_baseline_days}} days of history in the window.
CREATE OR REPLACE TABLE features.user_day_dense AS
WITH bounds AS (
    SELECT entity, min(day) AS first_day FROM features.user_day_base GROUP BY ALL
), max_day AS (
    SELECT max(day) AS last_day FROM auth_events
), grid AS (
    SELECT b.entity, CAST(g.day AS INTEGER) AS day
    FROM bounds b, max_day m, generate_series(b.first_day, m.last_day) AS g(day)
)
SELECT
    g.entity,
    g.day,
    b.n_events IS NOT NULL                                      AS is_active,
    {{zero_filled_counts}},
    -- Ratios are undefined on inactive days; window aggregates skip NULLs.
    b.n_fail / NULLIF(b.n_events, 0)                            AS fail_ratio,
    b.n_off_hours / NULLIF(b.n_events, 0)                       AS off_hours_ratio,
    b.n_new_dst_hosts / NULLIF(b.n_dst_hosts, 0)                AS new_dst_ratio,
    coalesce(b.is_first_day, FALSE)                             AS is_first_day
FROM grid g
LEFT JOIN features.user_day_base b USING (entity, day);

CREATE OR REPLACE TABLE features.user_day_baseline AS
SELECT
    d.*,
    count(*) OVER w                                             AS baseline_days,
    {{baseline_columns}}
FROM features.user_day_dense d
WINDOW w AS (PARTITION BY entity ORDER BY day RANGE BETWEEN {{window}} PRECEDING AND 1 PRECEDING);
