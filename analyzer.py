"""
analyzer.py - WatchTower: real-time SSH log analyzer and brute-force detector.

    python analyzer.py --file auth.log             # analyse a whole file
    python analyzer.py --file auth.log --follow    # keep watching for new lines (like tail -f)
"""
import argparse
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime

import pandas as pd
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------- parsing (regex)
LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$")
FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)")
ACCEPT_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)")


def parse_line(raw, year):
    """Turn one log line into a dict, or None if it is not a login event."""
    m = LINE_RE.match(raw.strip())
    if not m:
        return None
    for event, regex in (("failed", FAILED_RE), ("accepted", ACCEPT_RE)):
        hit = regex.search(m["msg"])
        if hit:
            time_ = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['clock']}", "%Y %b %d %H:%M:%S")
            return {"time": time_, "event": event, "user": hit["user"], "ip": hit["ip"],
                    "port": int(hit["port"]), "host": m["host"]}
    return None


# ---------------------------------------------------------------- detection logic
class BruteForceDetector:
    """Flags an IP that makes >= threshold failed logins inside a sliding window (seconds)."""

    def __init__(self, threshold, window):
        self.threshold = threshold
        self.window = window
        self.recent = defaultdict(deque)   # ip -> times of its recent failures
        self.history = defaultdict(list)   # ip -> every event seen from that ip
        self.blocked = {}                  # ip -> time it was blocked
        self.breached = set()              # blocked ips that later logged in successfully

    def process(self, ev):
        """Feed one event. Returns 'WARN', 'BLOCK', 'BREACH' or None."""
        ip = ev["ip"]
        self.history[ip].append(ev)

        if ev["event"] == "failed":
            q = self.recent[ip]
            q.append(ev["time"])
            while (ev["time"] - q[0]).total_seconds() > self.window:
                q.popleft()                                  # forget failures outside the window
            if len(q) >= self.threshold and ip not in self.blocked:
                self.blocked[ip] = ev["time"]
                return "BLOCK"
            if len(q) == max(2, self.threshold // 2) and ip not in self.blocked:
                return "WARN"

        elif ev["event"] == "accepted" and ip in self.blocked and ip not in self.breached:
            self.breached.add(ip)
            return "BREACH"
        return None


# ---------------------------------------------------------------- alerts + report
def stamp(ev):
    return ev["time"].strftime("%H:%M:%S")


def show_alert(kind, ev, det):
    ip = ev["ip"]
    if kind == "WARN":
        print(f"{Fore.YELLOW}[{stamp(ev)}] [WARN]    {ip} has {len(det.recent[ip])} failed logins "
              f"in {det.window}s - watching")
    elif kind == "BLOCK":
        print(f"{Fore.RED}{Style.BRIGHT}[{stamp(ev)}] [BLOCKED] {ip} - brute-force suspected "
              f"({len(det.recent[ip])} failures in {det.window}s)")
        print(f"{Fore.RED}           suggested firewall rule: sudo iptables -A INPUT -s {ip} -j DROP")
    elif kind == "BREACH":
        print(f"{Fore.MAGENTA}{Style.BRIGHT}[{stamp(ev)}] [CRITICAL] {ip} LOGGED IN as '{ev['user']}' "
              f"after being flagged - possible compromise!")


def write_report(ip, det, outdir="reports"):
    """Create an incident report (markdown) for one blocked IP."""
    os.makedirs(outdir, exist_ok=True)
    df = pd.DataFrame(det.history[ip])
    failed = df[df["event"] == "failed"]
    ok = df[df["event"] == "accepted"]
    minutes = max((df["time"].max() - df["time"].min()).total_seconds() / 60, 1 / 60)
    breached = ip in det.breached
    severity = "CRITICAL" if breached else "HIGH"

    path = os.path.join(outdir, f"incident_{ip.replace('.', '_')}.md")
    with open(path, "w") as f:
        f.write(f"# Security Incident Report - {ip}\n\n")
        f.write(f"**Severity:** {severity}\n\n**Type:** SSH brute-force attack\n\n")
        f.write(f"**Blocked at:** {det.blocked[ip]}\n\n")
        f.write("## Summary\n")
        f.write(f"- First seen: {df['time'].min()}\n- Last seen: {df['time'].max()}\n")
        f.write(f"- Failed logins: {len(failed)}\n- Successful logins: {len(ok)}\n")
        f.write(f"- Attack rate: {len(failed) / minutes:.1f} attempts/minute\n")
        f.write(f"- Distinct usernames tried: {failed['user'].nunique()}\n\n")
        f.write("## Usernames targeted\n")
        for user, n in failed["user"].value_counts().head(10).items():
            f.write(f"- {user}: {n}\n")
        if breached:
            f.write("\n## !! Possible compromise\n")
            for _, r in ok.iterrows():
                f.write(f"- {r['time']}: successful login as **{r['user']}** from {ip}\n")
        f.write("\n## Timeline (first 10 events)\n")
        for _, r in df.head(10).iterrows():
            f.write(f"- {r['time']} - {r['event']} - user `{r['user']}`\n")
        f.write("\n## Recommended actions\n")
        f.write(f"1. Block the address: `sudo iptables -A INPUT -s {ip} -j DROP`\n")
        if breached:
            f.write("2. Treat the account as compromised: lock it, reset the password, check for new SSH keys and running processes.\n")
        f.write("3. Disable password logins (use SSH keys) and consider fail2ban.\n")
    return path


def print_summary(det, all_events):
    print(f"\n{Style.BRIGHT}========== SUMMARY ==========")
    if not all_events:
        print("No login events found.")
        return
    df = pd.DataFrame(all_events)
    print(f"Login events : {len(df)}   (failed: {(df.event == 'failed').sum()}, "
          f"accepted: {(df.event == 'accepted').sum()})")
    table = (df.groupby("ip")
               .agg(failed=("event", lambda s: (s == "failed").sum()),
                    accepted=("event", lambda s: (s == "accepted").sum()),
                    users_tried=("user", "nunique"))
               .sort_values("failed", ascending=False).head(5))
    table["status"] = ["BLOCKED" if ip in det.blocked else "ok" for ip in table.index]
    print("\nTop sources of failed logins:")
    print(table.to_string())


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="WatchTower - SSH log analyzer and threat detector")
    ap.add_argument("--file", required=True, help="path to the auth log")
    ap.add_argument("--threshold", type=int, default=5, help="failed logins that trigger a block (default 5)")
    ap.add_argument("--window", type=int, default=60, help="sliding window in seconds (default 60)")
    ap.add_argument("--follow", action="store_true", help="keep watching the file for new lines")
    ap.add_argument("--year", type=int, default=datetime.now().year, help="year of the log (syslog has none)")
    args = ap.parse_args()

    det = BruteForceDetector(args.threshold, args.window)
    all_events, reports = [], {}

    def handle(raw):
        ev = parse_line(raw, args.year)
        if ev is None:
            return
        all_events.append(ev)
        kind = det.process(ev)
        if kind:
            show_alert(kind, ev, det)
        if kind == "BLOCK":
            reports[ev["ip"]] = write_report(ev["ip"], det)
        if kind == "BREACH":                      # refresh report with the compromise details
            reports[ev["ip"]] = write_report(ev["ip"], det)

    print(f"{Style.BRIGHT}WatchTower started - file: {args.file}, "
          f"threshold: {args.threshold} failures / {args.window}s\n")
    try:
        with open(args.file) as f:
            for raw in f:                          # existing lines
                handle(raw)
            while args.follow:                     # then keep tailing
                raw = f.readline()
                if raw:
                    handle(raw)
                else:
                    time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nStopped.")
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.file}  (run: python generate_logs.py)")

    print_summary(det, all_events)
    if reports:
        print("\nIncident reports written:")
        for ip, path in reports.items():
            print(f"  {ip} -> {path}")


if __name__ == "__main__":
    main()
