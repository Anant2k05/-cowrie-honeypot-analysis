# Cowrie Honeypot — Deployment & Log Analysis

A low-interaction SSH honeypot ([Cowrie](https://github.com/cowrie/cowrie)) deployed on AWS EC2
to observe real-world SSH probing/attack traffic, plus a small Python toolkit to
parse the resulting logs, geolocate source IPs, and chart the results.

## What is a honeypot, and why Cowrie?

A honeypot is a deliberately exposed, monitored system designed to attract and
record unauthorized access attempts, without exposing anything of real value.
Cowrie is a widely used **medium-interaction SSH/Telnet honeypot**: it presents
attackers with a fake Debian-like shell (fake filesystem, fake command
responses, a believable login banner) while logging every connection, every
credential tried, and every command typed — without giving the attacker a real
system to compromise. It was chosen here because it is the de facto standard
open-source SSH honeypot, well documented, and produces structured JSON logs
that are easy to analyze programmatically.

## Architecture

- **AWS EC2 instance** running Cowrie as a background service (systemd/screen),
  listening on the honeypot port.
- **Security group configuration:**
  - Port `2222` (Cowrie's fake SSH service) open to `0.0.0.0/0` — intentionally
    exposed to the public internet to attract scanning traffic.
  - Port `22` (real SSH, for management) restricted to the administrator's own
    IP address only.
- Cowrie logs every session as structured JSON events (`cowrie.session.connect`,
  `cowrie.client.version`, `cowrie.login.success`/`failed`, `cowrie.command.input`,
  `cowrie.session.closed`, etc.) to `var/log/cowrie/cowrie.json`, rotated daily.

## Methodology

- The honeypot ran for approximately 46 hours, from **2026-09-11 21:19 UTC**
  to **2026-09-13 19:38 UTC**, based on the timestamps present in the collected
  logs.
- Two raw daily JSON log files were pulled from the instance (`logs/cowrie.json`
  and `logs/cowrie.json.2026-09-11`) and analyzed locally with the scripts in
  this repo — no log data was modified, filtered, or supplemented.
- One IP, `223.187.114.68`, is the operator's own verification connection (used
  to confirm the honeypot was reachable and logging correctly). It is excluded
  from "attacker" statistics throughout but reported separately for transparency.

## Findings

Real output from `analyze_logs.py` and `geolocate_ips.py`, run against the logs
in this repo:

| Metric | Value |
|---|---|
| Total connections logged (all sources) | 3 |
| Unique source IPs (all sources) | 3 |
| Unique attacker IPs (excl. operator self-test) | 2 |
| Login attempts by attackers | 1 (1 succeeded, 0 failed) |
| Commands typed by attackers in the fake shell | 0 |
| Attacker session duration | min 120.0 s, max 326.5 s, avg 223.3 s (n=2) |

**Attacker IP breakdown:**

| IP | Connections | Geolocation | Notes |
|---|---|---|---|
| `172.31.43.78` | 1 | Not geolocatable — private/internal AWS address (RFC1918) | Source IP is identical to the honeypot's own instance IP; this is almost certainly another internal/loopback verification connection, not genuine internet-sourced attacker traffic. |
| `223.239.56.151` | 1 | Chennai, Tamil Nadu, India — ISP **Bharti Airtel Limited**, AS45609 | Logged in as `root`/`test456`, then disconnected with no shell commands typed. |

**Honest read of the data:** given the very small sample size, the dataset does
not support broad claims about attacker behavior. Of the two non-self-test
connections, one originated from a private AWS address identical to the
honeypot's own IP (not real internet traffic), leaving effectively **one**
plausible external contact — a single login with a simple test-style
credential pair and no follow-up activity. That single IP resolved to a
residential/mobile ISP (Bharti Airtel) in India, **not** cloud-hosted scanning
infrastructure — so, contrary to what's typical for busier honeypot
deployments, this dataset does not show evidence of automated cloud-based
scanning traffic. No brute-force credential stuffing, malware download
attempts, or botnet-style shell commands were observed in this window.

Charts generated from the real data are in [`charts/`](charts/):
- `connections_timeline.png` — every connection event plotted by timestamp
- `login_attempts.png` — the two login attempts observed (self-test + attacker)
- `connections_by_country.png` — geolocated attacker IPs by country

## Operational notes

During the monitoring window, a **security group misconfiguration** briefly
closed port 2222 to external traffic (an inbound rule was accidentally
tightened while doing unrelated maintenance on the instance). This was caught
during a routine reachability check and corrected. It's called out here
honestly because it's a real, useful lesson: **exposed research systems like
honeypots need periodic reachability verification**, since a silent
misconfiguration doesn't throw an error — it just results in an empty log file
that looks identical to "nobody happened to scan me today." The very low
connection count observed in this dataset (3 total connections in ~46 hours,
where public SSH honeypots typically see many automated scans within the first
few hours of exposure) is most plausibly explained by this reduced exposure
window rather than the honeypot being invisible to scanners.

## Limitations

- **Short monitoring window** (~46 hours) and **very small sample size** (3
  total connections, 1 genuinely plausible external contact after excluding
  self-tests). None of the findings above should be read as representative of
  typical internet SSH-scanning traffic.
- **Geolocation reflects network/hosting location, not physical attacker
  location.** `ip-api.com` resolves an IP to the location of the ISP/hosting
  provider that announces it, which is not necessarily where the person
  operating that connection physically is.
- The SG misconfiguration noted above means the effective exposure time was
  shorter than the nominal ~46-hour window, which likely suppressed the
  connection count further.

## Tech stack

- **Cowrie** — SSH/Telnet honeypot (Python, Twisted)
- **AWS EC2** — hosting, with security groups for network segmentation
- **Python 3** — log analysis (`analyze_logs.py`)
- **matplotlib** — charting
- **ip-api.com** — free IP geolocation API (`geolocate_ips.py`)

## Reproduce

```bash
# 1. Install and run Cowrie on an EC2 instance (see https://github.com/cowrie/cowrie)
#    - Open port 2222 to 0.0.0.0/0 in the security group
#    - Restrict port 22 to your own admin IP
#    - Let it run, then pull the JSON logs from var/log/cowrie/ into logs/

# 2. Install this project's dependencies
pip install -r requirements.txt

# 3. Analyze the logs (prints the full report + saves timeline/login charts)
python analyze_logs.py

# 4. Geolocate attacker IPs (saves geolocation_report.json + country chart)
python geolocate_ips.py
```

## Resume bullet points

- Deployed and operated a Cowrie SSH honeypot on AWS EC2 with segmented
  security-group rules (public honeypot port, admin-only management port),
  monitoring live internet-facing attack traffic over a multi-day window.
- Built a Python log-analysis pipeline to parse structured Cowrie JSON logs,
  extract attacker IPs/credentials/commands, and enrich findings with
  IP-geolocation lookups and matplotlib visualizations.
- Diagnosed and remediated a security-group misconfiguration that had
  silently reduced honeypot exposure, reinforcing the need for reachability
  verification on internet-facing research systems.

## What to screenshot

- `charts/connections_by_country.png` or `charts/connections_timeline.png` for
  a quick visual on GitHub/CV.
- The rendered README on GitHub (Findings + Operational notes sections show
  both the technical work and the honest reasoning behind it).
