# WatchTower: Real-Time Log Analyzer & Threat Detector

## The Problem
Servers generate thousands of log lines a day (SSH logins, web requests, errors). If a hacker tries to brute-force a server, it gets buried in the noise. Security analysts need a tool that reads these logs in real time and instantly flags brute-force attacks or suspicious IPs before they cause damage.

## The Solution
WatchTower is a lightweight, CLI-based cybersecurity tool that monitors SSH authentication logs in real time. It uses regex to parse log lines, Pandas to structure the data, and a sliding-window detector to catch brute-force attempts. When an attacker is flagged, it generates a security incident report automatically.

## Features
- **Regex log parsing** of `sshd` lines (failed and accepted logins)
- **Sliding-window detection**: an IP with `N` failed logins inside `T` seconds is flagged (default 5 in 60 s), so slow, harmless typos are not flagged
- **Three alert levels**, colour-coded in the terminal: `WARN` (yellow), `BLOCKED` (red), `CRITICAL` (magenta)
- **Compromise detection**: raises `CRITICAL` if a flagged IP later logs in successfully
- **Live mode** (`--follow`) that works like `tail -f`
- **Automatic incident reports** (Markdown) with timeline, targeted usernames, attack rate and recommended actions
- **Summary table** built with Pandas
- **Mock log generator** so you can test without a real server

## Tech Stack
- **Python 3.9+**
- **Pandas** (data structuring and analysis)
- **Colorama** (terminal text highlighting for alerts)
- **Regex** (log parsing)

## How to Use It
```bash
# Clone the repo
git clone https://github.com/yourusername/watchtower.git
cd watchtower

# Install dependencies
pip install -r requirements.txt

# Generate a mock log file for testing
python generate_logs.py

# Run the analyzer
python analyzer.py --file auth.log
```

### Real-time demo (two terminals)
```bash
# Terminal 1: simulate a server writing log lines live
python generate_logs.py --live
```
```bash
# Terminal 2 (start it right away): watch the same file as it grows
python analyzer.py --file auth.log --follow
```
Alerts appear as the lines arrive. Press `Ctrl+C` to stop and print the summary. In live mode the whole attack is replayed in a few seconds, so even the "slow scanner" can trip the warning.

### Options
| Option | Default | Meaning |
|---|---|---|
| `--file` | required | log file to analyse |
| `--threshold` | 5 | failed logins that trigger a block |
| `--window` | 60 | sliding window in seconds |
| `--follow` | off | keep watching for new lines |
| `--year` | current year | syslog lines have no year |

## Sample Output
```
[17:51:23] [BLOCKED] 198.51.100.23 - brute-force suspected (5 failures in 60s)
           suggested firewall rule: sudo iptables -A INPUT -s 198.51.100.23 -j DROP
[18:11:19] [BLOCKED] 198.51.100.99 - brute-force suspected (5 failures in 60s)
[18:11:43] [CRITICAL] 198.51.100.99 LOGGED IN as 'deploy' after being flagged - possible compromise!

Top sources of failed logins:
               failed  accepted  users_tried   status
198.51.100.23      40         0           10  BLOCKED
198.51.100.99      15         1            1  BLOCKED
192.0.2.77          3         0            1       ok
```
The slow scanner `192.0.2.77` (3 attempts, 10 minutes apart) is correctly **not** flagged.

## How the Detection Works
1. Each log line is matched with a regex and turned into an event: time, user, IP, result.
2. For every IP, WatchTower keeps the timestamps of its recent failed logins.
3. Failures older than the window are dropped; if the remaining count reaches the threshold, the IP is flagged.
4. A flagged IP that later gets an `Accepted` login triggers a `CRITICAL` alert.
5. An incident report is written to `reports/incident_<ip>.md`.

## Project Structure
```
watchtower/
├── analyzer.py        # parser, detector, alerts, reports
├── generate_logs.py   # creates a mock auth.log
├── requirements.txt
└── README.md
```

## Notes and Limitations
- Blocking is **simulated**: WatchTower prints the suggested `iptables` command but never runs it.
- It reads OpenSSH-style syslog lines only. Other formats need a new regex.
- All IPs in the mock log are from reserved documentation ranges (RFC 5737).
- Use it only on logs and servers you own or are authorised to monitor.

## Future Improvements
- Parse web-server (nginx / Apache) logs
- Optional automatic blocking and email/Telegram alerts
- GeoIP lookup for attacker IPs
- Detect distributed attacks across many IPs
