-- Peer groups, assigned per user from that user's OWN warm-up and never from the future.
--
--   warm-up      = the user's first {{warmup_days}} calendar days, starting at their first active day
--   peer_from    = first_day + {{warmup_days}}: the first day the assignment may be used
--   anchor       = most-used non-infrastructure remote host during the warm-up
--   peer_kind    = 'anchored' | 'infra_only' (remote logons, but only to infrastructure hosts)
--                | 'no_remote' (no remote network logons during the warm-up)
--
-- The assignment is frozen once made, so later behaviour (including an attack) can never move a
-- user. Users who first appear late get a group once their own warm-up is over, instead of never.
--
-- Infrastructure = hosts touched by more than {{max_host_user_frac}} of the users active in the
-- global warm-up (days < {{warmup_days}}); fixed, so later data cannot change it.
CREATE OR REPLACE TABLE features.peer_groups AS
WITH users AS (
    SELECT entity, min(day) AS first_day FROM features.user_day_base GROUP BY ALL
), remote AS (
    SELECT src_user, day, dst_comp
    FROM auth_events
    WHERE logon_type = 'Network'
      AND dst_comp IS NOT NULL AND dst_comp IS DISTINCT FROM src_comp
), global_warm AS (
    SELECT * FROM remote WHERE day < {{warmup_days}}
), infra AS (
    SELECT dst_comp
    FROM global_warm
    GROUP BY dst_comp
    HAVING count(DISTINCT src_user) > {{max_host_user_frac}} * (SELECT count(DISTINCT src_user) FROM global_warm)
), warm AS (
    -- Each user's own warm-up window.
    SELECT r.src_user, r.dst_comp, r.dst_comp IN (SELECT dst_comp FROM infra) AS is_infra
    FROM remote r JOIN users u ON u.entity = r.src_user
    WHERE r.day < u.first_day + {{warmup_days}}
), top_host AS (
    SELECT src_user, dst_comp AS anchor
    FROM (SELECT src_user, dst_comp, count(*) AS n FROM warm WHERE NOT is_infra GROUP BY ALL)
    -- Deterministic tie-break on host name.
    QUALIFY row_number() OVER (PARTITION BY src_user ORDER BY n DESC, dst_comp) = 1
), any_remote AS (
    SELECT DISTINCT src_user FROM warm
)
SELECT
    u.entity,
    u.first_day,
    u.first_day + {{warmup_days}}                    AS peer_from,
    t.anchor,
    CASE
        WHEN t.anchor IS NOT NULL THEN 'anchored'
        WHEN a.src_user IS NOT NULL THEN 'infra_only'
        ELSE 'no_remote'
    END                                              AS peer_kind
FROM users u
LEFT JOIN top_host t ON t.src_user = u.entity
LEFT JOIN any_remote a ON a.src_user = u.entity;

-- Effective group on day d, using only assignments already made (peer_from <= d):
--   anchored users share 'peer_<anchor>' once at least {{min_peer_group_size}} users with that anchor
--   are assigned; until then they are pooled into 'other'. Fallback kinds are their own groups.
-- Same-day robust deviation from that group: (x - median) / (1.4826 * MAD), MAD floored, NULL when
-- the group has fewer than {{min_peer_group_size}} members that day. Uses only same-day data from
-- other entities, available at end-of-day scoring time.
CREATE OR REPLACE TABLE features.user_day AS
WITH eligible AS (
    SELECT b.entity, b.day, p.anchor, p.peer_kind,
           count(*) FILTER (WHERE p.anchor IS NOT NULL)
               OVER (PARTITION BY p.anchor, b.day) AS anchor_size
    FROM features.user_day_baseline b
    JOIN features.peer_groups p USING (entity)
    WHERE b.day >= p.peer_from
), labelled AS (
    SELECT entity, day,
        CASE
            WHEN peer_kind <> 'anchored' THEN peer_kind
            WHEN anchor_size >= {{min_peer_group_size}} THEN 'peer_' || anchor
            ELSE 'other'
        END AS peer_group
    FROM eligible
), joined AS (
    SELECT b.*, coalesce(l.peer_group, 'unassigned') AS peer_group
    FROM features.user_day_baseline b
    LEFT JOIN labelled l USING (entity, day)
), stats AS (
    SELECT peer_group, day, count(*) AS peer_n, {{peer_stats}}
    FROM joined
    WHERE peer_group <> 'unassigned'
    GROUP BY peer_group, day
)
SELECT
    j.*,
    coalesce(s.peer_n, 0) AS peer_n,
    {{peer_columns}}
FROM joined j
LEFT JOIN stats s USING (peer_group, day)
ORDER BY entity, day;
