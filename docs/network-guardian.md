# Network Guardian (development branch)

NetWatch's development branch adds SQLite scan history, device trust profiles, and a Network Guardian tab.

## Setup

1. Build from the `NetWatch-Dashboard-Dev` branch using `docker build -t netwatch-dev .` or publish a separate development Docker tag. Keep the stable `latest` deployment untouched until tested.
2. Persist `/app/data` with a Docker volume (as in the included Compose file). The database is `/app/data/guardian.sqlite3`.
3. Scan a network once to create the baseline, then scan the *same target* again to see changes.
4. Open Network Guardian to mark devices as trusted and assign friendly names. Unknown means unreviewed, not dangerous.
5. Back up `./data` before testing or upgrading.

## Optional login

Set `NETWATCH_USERNAME=admin` and `NETWATCH_PASSWORD=<unique long password>` in your environment. If the password is omitted, NetWatch remains without a login for backwards compatibility. Login uses HTTP Basic authentication, which is **not encryption**. Use HTTPS behind a trusted reverse proxy if remotely accessed, and do not directly expose this scanner on the public internet.

The loopback-only `/healthz` route remains available for Docker's health check. Browser requests from a foreign origin cannot modify settings or profiles.

## How change detection works

- Comparison occurs only between successful scans of exactly the same target string.
- The first scan is a baseline and does not produce 'new device' alerts.
- Events include added/removed hosts, newly opened/closed ports and changed IPs when the MAC is available.
- A device's identity uses MAC when available or IP as fallback; without MAC lookup, DHCP changes may look like device churn.
- The last 100 snapshots per target and newest 2000 events are retained.
- Clearing the *current results* does not erase historical scans.
- Nmap scans are periodic snapshots, not continuous packet capture or instant intruder detection.
- Push notifications and authenticated vulnerability assessments are not included in this development build.

## Checks

Run `python -m unittest discover -s tests -v` and `docker build -t netwatch-dev .`. GitHub Actions runs syntax checks, tests, Docker builds and dependency auditing.
