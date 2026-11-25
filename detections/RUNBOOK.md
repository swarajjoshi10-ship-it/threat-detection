# Runbook: host fan-out with watch list

**Rule:** [host_fanout_rule.sql](host_fanout_rule.sql) · **Runner:** `python -m detections.rule`
· **Status:** prototype. The numbers below are post-hoc on LANL days 8–29 and not validated on fresh data.

## What it detects

A source host that suddenly authenticates **many accounts it never served before**. This is what
credential reuse and lateral movement look like from one foothold. MITRE ATT&CK:
- Valid Accounts (T1078);
- Remote Services (T1021);
- Use Alternate Authentication Material: Pass the Hash (T1550.002), when the new logons are NTLM.

| Stage | Fires when | Output |
|---|---|---|
| **Trigger** | `fanout = recent-new users / (1 + established users) >= threshold` and at least `min_new` recent-new users, on one day | `detections.fanout_triggers` |
| **Watch** | for `watch_days` after a host's latest trigger, its baseline stays frozen at its first trigger | `detections.fanout_host_alerts`, one row per watched host-day |
| **User alert** | a *suspect* user (first reached the host since its first trigger minus W) makes a remote logon from a watched host | `detections.fanout_user_alerts` |

The watch stage exists because of a real failure. With a plain 14-day window, the main LANL
attacker host had touched more than 100 accounts by day 14. Those accounts then aged into
"established", its score fell from 16.4 to 0.02, and thousands of hosts outranked it. Freezing
the baseline at the first trigger stops an attacker from becoming normal by staying around.

## Schedule and parameters

Run daily after the authentication logs for day *d* have landed. Rebuild `hostrisk.*` first, then
run the rule.

| Parameter | Default | How it was set |
|---|---|---|
| `w` | 14 days | pre-registered for v3 |
| `min_new` | 3 | so one new user on an empty host can't fire |
| `threshold` | 8.0 on LANL | label-free: the smallest value with ≤ 1 trigger a day on days 1–7 |
| `watch_days` | 30 | post-hoc; 14 gives the same result on LANL, 7 does not (see README) |

**Recalibrate the threshold monthly.** On LANL it fired about 1 time a day on days 1–7 but 20–30
times a day later on, as the network got busier and more pairs became new. A fixed threshold
drifts.

## Triage steps (target: 10 minutes per host)

1. **Is the host a known shared machine?** Jump hosts, VDI pools, admin and orchestration servers,
   and scanners fan out by design. Check the asset inventory. If it's legitimate, add it to the
   suppression list **with an owner and an expiry date**, never permanently.
2. **Who are the suspect users?** Look at `detections.fanout_user_alerts` for the host. Ask:
   - Are they service accounts, admins, or ordinary users?
   - Do ordinary users who have never used this host before now log in from it? That is the
     strongest signal.
3. **How did they authenticate?** NTLM from a workstation to many servers suggests pass-the-hash;
   Kerberos is less suspicious, but not cleared. Also check failed logons just before the successes.
4. **What happened on the destinations?** Check for new services, scheduled tasks, or remote
   execution on the hosts these users reached.
5. **Is there a change ticket?** Imaging, onboarding waves, or a new deployment tool explain a
   one-day spike. If there's a ticket, close the alert as benign and add a note.

**Escalate to incident response** when ordinary user accounts appear from a non-shared workstation
with no change ticket. Escalate immediately if they are NTLM, or if any suspect account is
privileged.

## Known limits

- **Noise:** in the post-hoc test, about 3% of user alerts on days 15–29 were malicious, at
  69 watched host-days a day. Triage by host, not by user; one host explains dozens of user alerts.
- **Growing watch list:** every trigger adds a host for `watch_days`. Clearing a host as benign
  should take it off the list. That isn't built yet.
- **Slow fan-out is missed:** an attacker who adds two new accounts a day never crosses the
  threshold. Day-over-day accumulation on watched hosts is the next thing to try.
- **Same machine names only:** NAT and DHCP churn break the "same host" assumption outside LANL.
