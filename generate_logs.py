"""
generate_logs.py - creates a MOCK sshd authentication log for testing WatchTower.

All IPs are from the reserved documentation ranges (RFC 5737), so no real
address is ever used.

Usage:
    python generate_logs.py                  # writes auth.log instantly
    python generate_logs.py --live           # appends lines slowly (real-time demo)
"""
import argparse
import random
import time
from datetime import datetime, timedelta

HOST = "watchtower-srv"
GOOD_USERS = ["alice", "bob", "carol", "dev", "deploy"]
OFFICE_IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.25", "203.0.113.40"]
GUESSES = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "pi", "user", "ftp", "guest"]

BRUTE_FORCER = "198.51.100.23"   # hammers the server -> should be blocked
SLOW_SCANNER = "192.0.2.77"      # only 3 tries, spread out -> should NOT be flagged
LUCKY_ATTACKER = "198.51.100.99" # brute forces and finally gets in -> CRITICAL


def line(ts, msg):
    pid = random.randint(1000, 30000)
    return f"{ts.strftime('%b %d %H:%M:%S')} {HOST} sshd[{pid}]: {msg}"


def build_events():
    """Return a list of (seconds_from_start, message), sorted by time."""
    random.seed(7)
    ev = []

    # normal traffic: successful logins + the occasional typo
    for _ in range(60):
        t = random.uniform(0, 3500)
        user, ip, port = random.choice(GOOD_USERS), random.choice(OFFICE_IPS), random.randint(30000, 60000)
        if random.random() < 0.1:
            ev.append((t, f"Failed password for {user} from {ip} port {port} ssh2"))
            ev.append((t + 4, f"Accepted password for {user} from {ip} port {port} ssh2"))
        else:
            ev.append((t, f"Accepted publickey for {user} from {ip} port {port} ssh2"))

    # 1) fast brute force: 40 attempts in about 2 minutes
    start = 1200
    for i in range(40):
        user = random.choice(GUESSES)
        ev.append((start + i * 3, f"Failed password for invalid user {user} from {BRUTE_FORCER} "
                                  f"port {random.randint(30000, 60000)} ssh2"))

    # 2) slow scanner: 3 attempts, 10 minutes apart (below the radar)
    for i in range(3):
        ev.append((300 + i * 600, f"Failed password for root from {SLOW_SCANNER} "
                                  f"port {random.randint(30000, 60000)} ssh2"))

    # 3) brute force that finally succeeds
    start = 2400
    for i in range(15):
        ev.append((start + i * 2, f"Failed password for deploy from {LUCKY_ATTACKER} "
                                  f"port {random.randint(30000, 60000)} ssh2"))
    ev.append((start + 32, f"Accepted password for deploy from {LUCKY_ATTACKER} port 40222 ssh2"))

    return sorted(ev)


def main():
    ap = argparse.ArgumentParser(description="Generate a mock auth.log")
    ap.add_argument("--out", default="auth.log")
    ap.add_argument("--live", action="store_true", help="append lines slowly with current timestamps")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between lines in --live mode")
    args = ap.parse_args()

    events = build_events()

    if not args.live:
        base = datetime.now() - timedelta(hours=1)
        with open(args.out, "w") as f:
            for secs, msg in events:
                f.write(line(base + timedelta(seconds=secs), msg) + "\n")
        print(f"Wrote {len(events)} log lines to {args.out}")
    else:
        open(args.out, "w").close()
        print(f"Appending to {args.out} every {args.delay}s - press Ctrl+C to stop")
        with open(args.out, "a") as f:
            for _, msg in events:
                f.write(line(datetime.now(), msg) + "\n")
                f.flush()
                time.sleep(args.delay)
        print("Done.")


if __name__ == "__main__":
    main()
