# Zombie candidate and idle-scan workflow

Scan **60 [N]** finds possible IPv4 idle-scan zombies; Scan **05 [S]** uses a freshly validated zombie to examine a separate target. Scan 71 uses the same validation/selection workflow. These remain terminal-controlled exercises.

## Scan 60: choose the scope

Choose OS-unknown discovered hosts, all discovered IPv4 hosts, or a manually supplied IP/CIDR/range/`-iL` file. OS-unknown includes TTL-only estimates. An empty stored scope stops with an explanation rather than silently expanding scope. Unknown OS is a selection hint, not evidence of a suitable IPID sequence.

Choose the TCP probe port (default 80). The hunter runs a SYN probe plus Nmap's `ipidseq` script with an explicit `ipidseq.probeport`. OS detection is optional; it is no longer an obligatory broad port/OS scan. A closed port can provide valid sequence replies, so an open port is not a suitability prerequisite. Filtering or missing script output can still prevent classification.

```bash
sudo .venv/bin/python main.py --customer CourseLab --interface any \
  --scan 60 --zombie-scope manual --targets 192.0.2.0/28 \
  --zombie-probe-port 80 --non-interactive
```

For an existing session, replace `--customer CourseLab` with `--resume /path/to/session`. Select `--zombie-scope unknown` or `all` to use its discovered hosts. Add `--zombie-os` only when wanted.

## Scan 05: select and freshly validate

After entering the actual scan target, select a saved candidate or enter IPv4[:probe-port] manually, then enter the target port list. A native OS IPID observation without a known probe port prompts for one. The scanner's own addresses and zombies inside the assessment target scope are rejected. Existing local-address detection and Nmap exclusions are retained.

Two fresh, short IPID checks are required by default. Non-incremental, missing, failed or interrupted checks produce specific reasons and retained evidence; failed validation prevents the idle scan. Successful validation is a point-in-time observation, not a guarantee: unrelated zombie traffic, per-destination counters, spoof filtering and routing can still defeat the final idle scan.

```bash
sudo .venv/bin/python main.py --customer CourseLab --interface any \
  --scan 05 --targets 203.0.113.10 --zombie 192.0.2.20:80 \
  --idle-ports 22,80,443 --zombie-checks 2 --non-interactive
```

Use documentation addresses only as examples; substitute your training systems. `--zombie-checks` accepts 1–3. `--dry-run` prints the scan plan without performing validation or scanning.

## Dashboard and retained evidence

The **Zombie candidates** tab shows the latest observation per IP/probe-port, classification, status, method, recorded/checked time, reason and raw evidence link when available. Its expandable history retains the latest 200 displayed checks; the database retains all checks. Imported observations are timestamped when imported; `ipidseq-validation` rows timestamp the fresh checks. Imported/native classifications remain candidates until freshly checked.

Re-importing an unchanged source does not duplicate its observations. Resuming an older session adds the tables and enriches imported XML; it preserves newer assessment observations. Validation artifacts do not expand assessment host lists or automatic audit scope. The legacy `zombie_candidates.txt` export remains an observation list, not a validation certificate. The dashboard cannot select candidates or launch scans.
