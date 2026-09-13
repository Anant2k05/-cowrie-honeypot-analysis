"""
analyze_logs.py

Parses Cowrie SSH honeypot JSON logs (all files under logs/) and prints a
summary of connections, login attempts, commands, and session durations.

Also generates two charts into charts/:
  - connections_timeline.png : connection events over time
  - login_attempts.png       : usernames/passwords tried (if any data exists)

The known operator self-test IP is excluded from "attacker" statistics but
reported separately, per the project scope.
"""

import glob
import json
import os
from datetime import datetime
from statistics import mean

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LOGS_DIR = "logs"
CHARTS_DIR = "charts"
SELF_TEST_IP = "223.187.114.68"


def load_events(logs_dir=LOGS_DIR):
    """Read every logs/cowrie.json* file and return a flat list of event dicts."""
    events = []
    log_files = sorted(glob.glob(os.path.join(logs_dir, "cowrie.json*")))
    for path in log_files:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events, log_files


def parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")


def analyze(events):
    connects = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
    versions = [e for e in events if e.get("eventid") == "cowrie.client.version"]
    logins_success = [e for e in events if e.get("eventid") == "cowrie.login.success"]
    logins_failed = [e for e in events if e.get("eventid") == "cowrie.login.failed"]
    commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
    closes = [e for e in events if e.get("eventid") == "cowrie.session.closed"]

    # Per-IP connection stats (all IPs, self-test included, split out later)
    ip_stats = {}
    for e in connects:
        ip = e.get("src_ip")
        ts = parse_ts(e["timestamp"])
        if ip not in ip_stats:
            ip_stats[ip] = {"count": 0, "first_seen": ts, "last_seen": ts}
        ip_stats[ip]["count"] += 1
        ip_stats[ip]["first_seen"] = min(ip_stats[ip]["first_seen"], ts)
        ip_stats[ip]["last_seen"] = max(ip_stats[ip]["last_seen"], ts)

    attacker_ip_stats = {ip: s for ip, s in ip_stats.items() if ip != SELF_TEST_IP}
    self_test_stats = ip_stats.get(SELF_TEST_IP)

    durations = [e["duration_ms"] for e in closes if "duration_ms" in e]
    attacker_durations = [
        e["duration_ms"] for e in closes
        if "duration_ms" in e and e.get("src_ip") != SELF_TEST_IP
    ]

    login_attempts = []
    for e in logins_success + logins_failed:
        login_attempts.append({
            "src_ip": e.get("src_ip"),
            "username": e.get("username"),
            "password": e.get("password"),
            "success": e.get("eventid") == "cowrie.login.success",
            "timestamp": e.get("timestamp"),
        })

    attacker_logins = [a for a in login_attempts if a["src_ip"] != SELF_TEST_IP]

    attacker_commands = [c for c in commands if c.get("src_ip") != SELF_TEST_IP]
    self_test_commands = [c for c in commands if c.get("src_ip") == SELF_TEST_IP]

    return {
        "connects": connects,
        "versions": versions,
        "ip_stats": ip_stats,
        "attacker_ip_stats": attacker_ip_stats,
        "self_test_stats": self_test_stats,
        "durations": durations,
        "attacker_durations": attacker_durations,
        "login_attempts": login_attempts,
        "attacker_logins": attacker_logins,
        "commands": commands,
        "attacker_commands": attacker_commands,
        "self_test_commands": self_test_commands,
        "logins_success": logins_success,
        "logins_failed": logins_failed,
    }


def print_report(stats, log_files):
    print("=" * 70)
    print("COWRIE HONEYPOT LOG ANALYSIS")
    print("=" * 70)
    print(f"\nLog files parsed: {', '.join(log_files)}")

    total_connections = len(stats["connects"])
    unique_all_ips = len(stats["ip_stats"])
    unique_attacker_ips = len(stats["attacker_ip_stats"])

    print(f"\nTotal connections (all sources): {total_connections}")
    print(f"Unique source IPs (all sources): {unique_all_ips}")
    print(f"Unique attacker IPs (excluding self-test): {unique_attacker_ips}")

    if stats["self_test_stats"]:
        s = stats["self_test_stats"]
        print(f"\nOperator's own verification test IP ({SELF_TEST_IP}):")
        print(f"  connections={s['count']}  first_seen={s['first_seen']}  last_seen={s['last_seen']}")

    print("\n--- Attacker IP table (connection count, first seen, last seen) ---")
    if not stats["attacker_ip_stats"]:
        print("  (none - no non-self-test connections were logged)")
    for ip, s in sorted(stats["attacker_ip_stats"].items(), key=lambda kv: -kv[1]["count"]):
        note = ""
        if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.") or (
            ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31
        ):
            note = "  [private/internal RFC1918 address - not a public attacker]"
        print(f"  {ip:16s}  count={s['count']}  first={s['first_seen']}  last={s['last_seen']}{note}")

    print("\n--- Login attempts (excluding self-test) ---")
    if not stats["attacker_logins"]:
        print("  (none)")
    for a in stats["attacker_logins"]:
        result = "SUCCESS" if a["success"] else "FAILED"
        print(f"  [{result}] {a['src_ip']}  {a['username']}/{a['password']}  @ {a['timestamp']}")
    succ = sum(1 for a in stats["attacker_logins"] if a["success"])
    fail = sum(1 for a in stats["attacker_logins"] if not a["success"])
    print(f"  Totals: {succ} succeeded, {fail} failed  (n={len(stats['attacker_logins'])})")

    if stats["self_test_stats"]:
        self_logins = [a for a in stats["login_attempts"] if a["src_ip"] == SELF_TEST_IP]
        print(f"\n  Operator self-test login attempts (excluded above): {len(self_logins)}")
        for a in self_logins:
            result = "SUCCESS" if a["success"] else "FAILED"
            print(f"    [{result}] {a['username']}/{a['password']} @ {a['timestamp']}")

    print("\n--- Commands run by attackers inside the fake shell (excluding self-test) ---")
    if not stats["attacker_commands"]:
        print("  (none - no non-self-test session typed any shell commands)")
    for c in stats["attacker_commands"]:
        print(f"  {c['src_ip']}  '{c.get('input')}'  @ {c['timestamp']}")

    if stats["self_test_commands"]:
        print(f"\n  Operator self-test commands (excluded above, n={len(stats['self_test_commands'])}):")
        for c in stats["self_test_commands"]:
            print(f"    '{c.get('input')}'  @ {c['timestamp']}")

    print("\n--- Session duration stats (ms) ---")
    if stats["durations"]:
        print(f"  All sessions:      min={min(stats['durations'])}  max={max(stats['durations'])}  avg={mean(stats['durations']):.0f}  (n={len(stats['durations'])})")
    if stats["attacker_durations"]:
        print(f"  Attacker sessions: min={min(stats['attacker_durations'])}  max={max(stats['attacker_durations'])}  avg={mean(stats['attacker_durations']):.0f}  (n={len(stats['attacker_durations'])})")
    else:
        print("  Attacker sessions: (no non-self-test sessions with a recorded duration)")

    print("\n" + "=" * 70)
    print(f"NOTE: This is a very small dataset ({total_connections} total connections "
          f"across {len(log_files)} log file(s)). Findings below reflect exactly what "
          f"was captured during the monitoring window - no data has been extrapolated "
          f"or invented.")
    print("=" * 70)


def make_charts(stats):
    os.makedirs(CHARTS_DIR, exist_ok=True)

    # --- Timeline of connection events ---
    plt.figure(figsize=(9, 4))
    if stats["connects"]:
        times = sorted(parse_ts(e["timestamp"]) for e in stats["connects"])
        ips = [e.get("src_ip") for e in sorted(stats["connects"], key=lambda e: e["timestamp"])]
        colors = ["tab:red" if ip == SELF_TEST_IP else "tab:blue" for ip in ips]
        plt.scatter(times, [1] * len(times), c=colors, s=80, zorder=3)
        for t in times:
            plt.axvline(t, color="lightgray", linewidth=0.5, zorder=1)
        plt.yticks([])
        plt.xticks(rotation=30, ha="right")
        plt.title(f"Connection events over time (n={len(times)})\nred = operator self-test, blue = other source")
    else:
        plt.text(0.5, 0.5, "No connection events recorded", ha="center", va="center")
        plt.title("Connection events over time")
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, "connections_timeline.png"), dpi=150)
    plt.close()

    # --- Login attempts (username/password pairs tried) ---
    plt.figure(figsize=(8, 4))
    attempts = stats["login_attempts"]
    if attempts:
        labels = [f"{a['username']}/{a['password']}" for a in attempts]
        colors = ["tab:green" if a["success"] else "tab:red" for a in attempts]
        plt.bar(range(len(labels)), [1] * len(labels), color=colors)
        plt.xticks(range(len(labels)), labels, rotation=30, ha="right")
        plt.ylabel("attempt")
        plt.title(f"Login attempts observed (n={len(attempts)}) - green=success, red=failed\n"
                  f"Sample size is very small; not statistically representative.")
    else:
        plt.text(0.5, 0.5, "No login attempts recorded", ha="center", va="center")
        plt.title("Login attempts observed")
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, "login_attempts.png"), dpi=150)
    plt.close()

    print(f"\nCharts saved to {CHARTS_DIR}/: connections_timeline.png, login_attempts.png")


if __name__ == "__main__":
    events, log_files = load_events()
    stats = analyze(events)
    print_report(stats, log_files)
    make_charts(stats)
