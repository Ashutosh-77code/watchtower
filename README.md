# WatchTower

A small Python tool that reads a server's SSH login log and tells you when someone is trying to guess their way in.

![WatchTower catching an attack live](screenshot.png)

## Why I built it

A busy server writes thousands of login lines a day. If someone starts guessing passwords, those failed attempts sit between all the normal ones, and nobody scrolling through the file by hand is going to notice in time. I wanted to see how a tool could spot that pattern on its own, so I built one from scratch to find out.

## What it does

WatchTower reads the log line by line and keeps count of failed logins for every IP address. If one address fails 5 times within 60 seconds, it gets flagged and a red alert appears. If that same address then manages to log in, you get a louder alert, because the attacker may have guessed the password.

Every flagged IP also gets a short incident report written for it, with how fast the attempts came in, which usernames were tried, a timeline, and what to do next. You can see a real one in [`examples/sample_incident_report.md`](examples/sample_incident_report.md).

The alerts come in three colours:
- **Yellow `WARN`**: an IP has a couple of failed logins, keeping an eye on it
- **Red `BLOCKED`**: that's an attack, here's the firewall rule you'd use
- **Magenta `CRITICAL`**: a flagged IP just logged in successfully

## Try it in two minutes

You need Python 3.9 or newer.

```bash
git clone https://github.com/yourusername/watchtower.git
cd watchtower
pip install -r requirements.txt

python generate_logs.py                  # makes a fake auth.log to play with
python analyzer.py --file auth.log       # reads it and flags the attackers
```

The fake log has two attackers (one of them gets in), one slow scanner that should be ignored, and some normal users. So you know what the right answer looks like.

## Play the attacker

This is the fun part. Open two terminals.

```bash
# Terminal 1: start watching
python analyzer.py --file auth.log --follow
```
```bash
# Terminal 2: be the attacker
python simulate_attack.py                          # 10 failed logins, so you get blocked
python simulate_attack.py --attempts 3             # only 3, so nothing happens
python simulate_attack.py --attempts 8 --success   # gets in, so CRITICAL
```

Press `Ctrl+C` in the first terminal to stop it and see a summary table.

You can also change how strict it is: `--threshold` (how many failures) and `--window` (how many seconds). For example `python analyzer.py --file auth.log --threshold 3 --window 30`.

## How it decides

For each IP, it remembers the times of its recent failed logins and forgets anything older than the window. When the number it still remembers reaches the threshold, that IP is flagged. That is why a person who mistypes a password twice isn't treated like an attacker, and why an attacker who is slow and patient (3 tries, 10 minutes apart) stays under the radar. That last part is a real weakness of this approach, and I've left it as it is on purpose.

## Does it actually work?

I tested it two ways.

1. The fake log was built with a known answer. WatchTower flags exactly the two attackers, reports the one who got in, and leaves everyone else alone.
2. `python test_watchtower.py` runs 7 checks covering the log parser, the 5-in-60-seconds rule, slow attempts being ignored, each IP being counted separately, and the critical alert. I also broke the detector on purpose once to make sure the tests would fail when they should.

Honest caveat: I've only run it on generated logs, not on a real server.

## What it doesn't do

- **It doesn't block anyone.** It prints the `iptables` command you could use, but never runs it. I didn't want a script changing firewall rules on its own.
- **It only understands OpenSSH-style log lines.** Web server logs would need a new regex.
- **A slow attacker can slip past it**, as explained above.
- It's for logs and servers you own or are allowed to monitor.

## What's in the folder

```
watchtower/
├── analyzer.py          # the detector: parsing, alerts, reports
├── generate_logs.py     # makes the fake auth.log
├── simulate_attack.py   # lets you play the attacker
├── test_watchtower.py   # the 7 checks
├── examples/            # a sample incident report
├── requirements.txt
└── README.md
```

## Built with

Python, Pandas for the summary tables, Colorama for the coloured alerts, and a handful of regular expressions to read the log.

## Where I'd take it next

Reading nginx/Apache logs, sending an alert to Telegram or email, looking up where an attacking IP is located, and catching attacks spread across many different IPs.

All the IP addresses in the fake logs come from ranges reserved for documentation, so none of them belong to anyone real.
