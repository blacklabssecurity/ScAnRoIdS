# Validation record

Validated in a Debian 13 execution environment using Python 3.12. Python 3.11 compatibility was additionally checked by parsing application sources with the 3.11 grammar; running a full interpreter/version matrix remains a downstream CI task.

## Automated checks

**77 tests passed**, including the optional checks below:

- Nmap XML and GNMAP import, IPv6 address selection, discovery-only hosts, missing TTL, explicit closed/open|filtered states, malformed XML fallback and unchanged state on failed import.
- Repeated imports, history retention, legacy database backup/deduplication, session resumption, complete domain-controller port matching and sanitized service paths.
- Exact menu IDs, command argument quoting, input-file expansion, managed output/scope protection, transport-specific audit plans and capture filters.
- Real local subprocess output/error streaming, nonzero exits, quiet-process timeout, cancellation/reaping, unavailable commands, capture startup failure, successful dumpcap startup/finalization with a controlled stub, dumpcap-specific dependency checks, bounded log rotation.
- Viewer login/CSRF, anonymous access denial, file containment/symlinks, absence of HTTP scan-control routes, event replay, stale heartbeat, logout and evidence-derived topology.
- SMB adapter eligibility, SNMP single-community file handling and session comparisons.
- **Real Nmap 7.95**: a TCP connect scan against a temporary HTTP service bound to **127.0.0.1 only**, verifying process state, -oA artifact production and import of the observed open port. The test deliberately bypasses self-exclusion only inside the test; production retains self-exclusion.
- Nmap `--script-help` validated the named scripts configured in profiles. This does not send scan traffic.
- **libpcap 1.10.5** compiled ten generated BPF variants offline: CIDR, ARP, DNS, ICMPv6, SCTP, EIGRP, OSPF, mixed TCP/UDP, IPv6/port ranges and idle-scan zombie scope. No live interface was opened.

The standard command runs the unit/process/API suite and skips the optional Nmap/libpcap checks unless explicitly enabled:

```bash
.venv/bin/python -m pytest -q
SCANROIDS_NMAP_INTEGRATION=1 .venv/bin/python -m pytest -q tests/test_nmap_integration.py
SCANROIDS_LIBPCAP=/path/to/libpcap.so.0.8 .venv/bin/python -m pytest -q tests/test_capture_filters.py
```

Additional checks passed:

```bash
.venv/bin/ruff check main.py config.py core modules tests
.venv/bin/ruff format --check main.py config.py core modules tests
node --check web/static/js/dashboard.js
bash -n setup_scanRoids.sh
```

CLI smoke checks covered batch import, a dry-run mixed-protocol management profile, dependency diagnostics and course-profile overrides.

## Browser checks

Headless Chromium exercised the real Waitress/Flask server with the bundled synthetic fixture:

- Login and current host/service counts.
- Search and port sorting retained through browser reload.
- Service evidence dialog and host-only inventory.
- Measured topology rendering and artifact links.
- Desktop screenshot inspection and a 390-pixel mobile viewport without page overflow.
- Three additional independently authenticated browser contexts.
- No JavaScript page errors.

`docs/images/dashboard.png` is the inspected desktop preview. To repeat the browser smoke check, install `requirements-browser.txt`, start the README synthetic demo, then run:

```bash
SCANROIDS_TEST_URL=http://127.0.0.1:8888 \
SCANROIDS_TEST_PASSWORD='your-demo-password' \
.venv/bin/python tests/browser_smoke.py
```

Set `SCANROIDS_CHROMIUM` if your browser is elsewhere. Install Playwright's Chromium separately if you prefer its bundled browser.

## Lab acceptance still needed

This environment is not your Kali installation. Live Tshark/dumpcap permissions and actual PCAP finalization were not tested here; capture startup failure and process cleanup were exercised with controlled stubs, and BPF syntax was checked with real libpcap.

Gowitness/Chromium, enum4linux/Samba, SNMP, NFS mounting and Gobuster require end-to-end tests against your training services and installed tool versions. Raw discovery, OS detection, decoys, idle scans, fragmentation, routing-protocol discovery, SCTP and proxy behavior depend on lab interfaces, routing and target responses. They have validated command plans and recorded diagnostics, not a claim of universal live compatibility.

For first acceptance on Kali, run one small lab subnet through discovery → inspect raw output and PCAP → audit discovered ports → compare dashboard counts → exercise only the installed adapters → stop with Ctrl+C → resume/import the session. Keep a copy of an existing session before trying migration on valuable historical data.

## Port uncertainty and analysis-readiness regression checks

Additional tests verify uncertain states are visible without inflating confirmed-open totals or entering automatic audit/tool scope; exact grouped XML ports and single-summary complements; refusal to invent ports from ambiguous counts; legacy import enrichment without overwriting newer state; plugin startup errors with exit code zero; healthy startup; permission/zero-packet guide text; and skipping unhealthy Tshark analysis in favor of available alternatives.

Browser checks for this update also passed for visible uncertainty/state/reason, unchanged confirmed-open counts, persistence of the state filter, no host-list link for unconfirmed services, withheld Tshark recipes under a simulated plugin failure, an available tcpdump alternative, and mobile layout without page overflow. No JavaScript page errors were observed.

## Zombie classification compatibility

Nine additional regression cases check actual NSE `Incremental!` output, native classification and debug suffixes, rejection of broken/non-incremental labels, candidate export, and pre-idle validation without adding the zombie to assessment targets. The synthetic fixture now uses the actual NSE punctuation. The local Nmap 7.95 ipidseq script was inspected to confirm its returned classification text. These tests do not claim a live end-to-end idle scan was performed.
