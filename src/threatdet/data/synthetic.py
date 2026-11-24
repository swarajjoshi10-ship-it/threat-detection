"""Synthetic authentication logs in the exact LANL auth.txt / redteam.txt format.

Purpose: develop and test the pipeline without the real data. It is NOT evidence that a model
works; results on synthetic data are only sanity checks. The generator deliberately includes:

* normal users with department-specific servers (gives peer groups real structure),
* machine accounts and ANONYMOUS LOGON noise (must be filtered by ingestion),
* benign anomalies -- admin "sweeps" across many hosts (sometimes in a late maintenance window)
  and users "travelling" to an unfamiliar workstation -- so naive rules generate false positives,
* two attack styles: noisy lateral movement (NTLM burst to many new hosts, often off-hours) and
  stealthy movement (2-3 hosts, business hours, Kerberos), so not every attack is easy.

Formats (no header, comma-separated):
  auth.txt:    time,src_user@domain,dst_user@domain,src_comp,dst_comp,auth_type,logon_type,orientation,outcome
  redteam.txt: time,user@domain,src_comp,dst_comp

    python -m threatdet.data.synthetic [--config config/default.toml] [--out data/raw/synthetic]
"""

from __future__ import annotations

import argparse
import gzip
import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from threatdet.config import Config, load_config

SECONDS_PER_DAY = 86_400
DOMAIN = "DOM1"
DC = "C1"  # domain controller
GLOBAL_SERVERS = ["C2", "C3", "C4", "C5"]  # file/mail/print servers everyone touches
# Hour-of-day weights for a typical office worker (dataset clock).
_HOUR_W = np.array([1, 1, 1, 1, 1, 2, 4, 10, 30, 45, 45, 40, 30, 40, 45, 45, 40, 30, 12, 6, 4, 3, 2, 1], float)
HOUR_P = _HOUR_W / _HOUR_W.sum()


@dataclass
class User:
    name: str
    dept: int
    home: str
    activity: float
    fail_rate: float
    is_admin: bool = False
    is_compromised: bool = False


@dataclass
class World:
    users: list[User]
    dept_servers: list[list[str]]
    workstations: list[str]
    all_hosts: list[str]


@dataclass
class Output:
    auth: list[tuple] = field(default_factory=list)
    redteam: list[tuple] = field(default_factory=list)
    truth: list[dict] = field(default_factory=list)


def build_world(cfg: Config, rng: np.random.Generator) -> World:
    s = cfg["synthetic"]
    n_users, n_dept, n_srv = s["n_users"], s["n_departments"], s["n_servers_per_department"]
    next_id = 10
    dept_servers = []
    for _ in range(n_dept):
        dept_servers.append([f"C{next_id + i}" for i in range(n_srv)])
        next_id += n_srv
    workstations = [f"C{next_id + i}" for i in range(int(n_users * 1.3))]  # some spare machines
    users = []
    for i in range(n_users):
        users.append(User(
            name=f"U{i + 1}",
            dept=int(rng.integers(n_dept)),
            home=workstations[i],
            activity=float(rng.lognormal(mean=np.log(40), sigma=0.5)),
            fail_rate=float(rng.choice([0.01, 0.02, 0.08], p=[0.6, 0.3, 0.1])),
        ))
    order = rng.permutation(n_users)
    for idx in order[: s["n_admin_users"]]:
        users[idx].is_admin = True
    for idx in order[s["n_admin_users"]: s["n_admin_users"] + s["n_compromised_users"]]:
        users[idx].is_compromised = True
    all_hosts = [DC, *GLOBAL_SERVERS, *[h for d in dept_servers for h in d], *workstations]
    return World(users, dept_servers, workstations, all_hosts)


def _event(t: int, user: str, src: str, dst: str, auth: str, logon: str, orient: str, ok: bool) -> tuple:
    u = f"{user}@{DOMAIN}"
    return (t, u, u, src, dst, auth, logon, orient, "Success" if ok else "Fail")


def normal_day(u: User, day: int, w: World, rng: np.random.Generator, out: Output, src_override: str | None = None):
    weekend = day % 7 in (5, 6)
    n = rng.poisson(u.activity * (0.12 if weekend else 1.0))
    if n == 0:
        return
    shift = int(rng.integers(-1, 2))  # personal schedule offset
    hours = (rng.choice(24, size=n, p=HOUR_P) + shift) % 24
    secs = rng.integers(0, 3600, size=n)
    kind = rng.choice(4, size=n, p=[0.25, 0.35, 0.30, 0.10])  # local, DC, dept server, global server
    rare = rng.random(n) < 0.01
    fails = rng.random(n) < u.fail_rate
    src = src_override or u.home
    for h, sec, k, r, f in zip(hours, secs, kind, rare, fails):
        t = day * SECONDS_PER_DAY + int(h) * 3600 + int(sec)
        if r:
            dst = w.all_hosts[int(rng.integers(len(w.all_hosts)))]
            out.auth.append(_event(t, u.name, src, dst, "Kerberos", "Network", "LogOn", not f))
        elif k == 0:
            out.auth.append(_event(t, u.name, src, src, "Negotiate", str(rng.choice(["Interactive", "Unlock"])), "LogOn", not f))
        elif k == 1:
            out.auth.append(_event(t, u.name, src, DC, "Kerberos", "Network", str(rng.choice(["TGS", "TGT"])), not f))
        elif k == 2:
            dst = w.dept_servers[u.dept][int(rng.integers(len(w.dept_servers[u.dept])))]
            auth = str(rng.choice(["Kerberos", "NTLM", "Negotiate"], p=[0.8, 0.1, 0.1]))
            out.auth.append(_event(t, u.name, src, dst, auth, "Network", "LogOn", not f))
        else:
            dst = GLOBAL_SERVERS[int(rng.integers(len(GLOBAL_SERVERS)))]
            out.auth.append(_event(t, u.name, src, dst, "Kerberos", "Network", "LogOn", not f))


def admin_sweep(u: User, day: int, w: World, rng: np.random.Generator, out: Output):
    """Benign: patching/inventory across many hosts. Sometimes in a late maintenance window."""
    late = rng.random() < 0.4
    start_h = int(rng.integers(21, 23)) if late else int(rng.integers(9, 15))
    targets = rng.choice(w.workstations, size=int(rng.integers(20, 60)), replace=False)
    t = day * SECONDS_PER_DAY + start_h * 3600
    for dst in targets:
        t += int(rng.integers(5, 60))
        out.auth.append(_event(t, u.name, u.home, str(dst), "Negotiate", "Network", "LogOn", rng.random() > 0.03))
    out.truth.append({"type": "benign_admin_sweep", "user": u.name, "day": day, "n_hosts": len(targets), "late": late})


def attack(u: User, day: int, w: World, rng: np.random.Generator, out: Output, stealthy: bool):
    if stealthy:
        hour, n_hops, auth = int(rng.integers(10, 16)), int(rng.integers(2, 4)), "Kerberos"
    else:
        hour = int(rng.choice([1, 2, 3, 22, 23, 10, 14]))
        n_hops, auth = int(rng.integers(8, 25)), "NTLM"
    t = day * SECONDS_PER_DAY + hour * 3600 + int(rng.integers(0, 1800))
    src = u.home
    targets = rng.choice([h for h in w.workstations if h != u.home], size=n_hops, replace=False)
    day_end = (day + 1) * SECONDS_PER_DAY - 1
    for dst in targets:
        t = min(t + int(rng.integers(20, 400)), day_end)  # keep the scenario inside its day
        if not stealthy and rng.random() < 0.3:  # failed guess before success; not a redteam row
            out.auth.append(_event(t - 3, u.name, src, str(dst), auth, "Network", "LogOn", False))
        out.auth.append(_event(t, u.name, src, str(dst), auth, "Network", "LogOn", True))
        out.redteam.append((t, f"{u.name}@{DOMAIN}", src, str(dst)))
        if rng.random() < 0.3:  # pivot: continue from the newly compromised host
            src = str(dst)
    out.truth.append({"type": "attack_stealthy" if stealthy else "attack_noisy", "user": u.name, "day": day,
                      "n_hosts": n_hops, "hour": hour})


def machine_noise(day: int, w: World, rng: np.random.Generator, out: Output):
    for host in rng.choice(w.workstations, size=len(w.workstations) // 2, replace=False):
        t = day * SECONDS_PER_DAY + int(rng.integers(SECONDS_PER_DAY))
        out.auth.append((t, f"{host}$@{DOMAIN}", f"{host}$@{DOMAIN}", host, DC, "Kerberos", "Network", "TGS", "Success"))
    for _ in range(50):
        t = day * SECONDS_PER_DAY + int(rng.integers(SECONDS_PER_DAY))
        src = str(rng.choice(w.workstations))
        out.auth.append((t, "ANONYMOUS LOGON@C586", "ANONYMOUS LOGON@C586", src, "C586", "NTLM", "Network", "LogOn", "Success"))


def generate(cfg: Config) -> Output:
    rng = np.random.default_rng(cfg.seed)
    s = cfg["synthetic"]
    w = build_world(cfg, rng)
    out = Output()
    compromised = [u for u in w.users if u.is_compromised]
    attack_days = set(s["attack_days"])
    for day in range(s["n_days"]):
        attackers: list[User] = []
        if day in attack_days and compromised:
            attackers = [u for u in compromised if rng.random() < 0.5] or [compromised[int(rng.integers(len(compromised)))]]
        for u in w.users:
            travel = (not u.is_admin) and rng.random() < s["p_travel_per_user_day"]
            if travel:
                away = str(rng.choice(w.workstations))
                out.truth.append({"type": "benign_travel", "user": u.name, "day": day, "src": away})
            normal_day(u, day, w, rng, out, src_override=away if travel else None)
            if u.is_admin and day % 7 not in (5, 6) and rng.random() < s["p_admin_sweep_per_day"]:
                admin_sweep(u, day, w, rng, out)
            if u in attackers:
                attack(u, day, w, rng, out, stealthy=rng.random() < 0.5)
        machine_noise(day, w, rng, out)
    out.auth.sort(key=lambda r: r[0])
    out.redteam.sort(key=lambda r: r[0])
    return out


def write(out: Output, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with gzip.open(dest / "auth.txt.gz", "wt", newline="\n") as f:
        f.writelines(",".join(map(str, r)) + "\n" for r in out.auth)
    with gzip.open(dest / "redteam.txt.gz", "wt", newline="\n") as f:
        f.writelines(",".join(map(str, r)) + "\n" for r in out.redteam)
    # Scenario ground truth for error analysis only (which FPs are admin sweeps, which misses are stealthy).
    (dest / "scenarios.json").write_text(json.dumps(out.truth, indent=1))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Generate synthetic LANL-format auth logs.")
    ap.add_argument("--config", default=None)
    ap.add_argument("--out", type=Path, default=None, help="default: <raw_dir>/synthetic")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    dest = args.out or cfg.path("raw_dir") / "synthetic"
    out = generate(cfg)
    write(out, dest)
    print(f"wrote {len(out.auth):,} auth events, {len(out.redteam):,} redteam events, "
          f"{len(out.truth):,} scenarios -> {dest}")


if __name__ == "__main__":
    main()
