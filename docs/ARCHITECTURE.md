# Architecture and extension points

## Instructor and viewers

One controller owns a session through a filesystem lock. The controller starts/stops subprocess groups, initializes the session, runs imports and offers tools. The dashboard exposes authenticated viewing endpoints plus login/logout. No HTTP endpoint starts/stops a scan or modifies results.

```text
Instructor terminal / saved course profile
           |
      main.py controller
           |
  scan registry -> scanner -> process runner -> Nmap / tool adapter
                                 |                  |
                             capture/logs        -oA artifacts
                                 |                  |
                              event log       parser/importer
                                 |                  |
                                 +---- SQLite ------+
                                         |
                              authenticated LAN viewers
```

The dashboard uses local static assets, an event stream for logs and periodic result snapshots. Filtering, sorting, pagination and selected tab are stored in each viewer browser per session. It works without internet access after installation.

## Persistent data

A unique session contains `session.json`, `artifacts/`, `targets/`, `pcap/`, and `logs/`. The default root is `/tools/scans/ScAnRoIdS`; use `--data-dir` or `SCANROIDS_DATA_DIR` to change it. Code and data roots are independent. Date/time fields are preserved on resume; customer names with underscores work.

`artifacts/session.db` uses WAL mode, short transactions and a busy timeout. Tables:

- `session_info`: operator, phase, current command and lifecycle status.
- `hosts`: host inventory, including discovery-only and DNS-list observations.
- `scan_results`: current observation for each address/port/protocol identity, including non-open states.
- `imports`: content-addressed raw normalized observations for history and topology. Reimporting identical bytes does not duplicate results or roll back a newer observation.
- `jobs`: execution status, command, exit code, heartbeat and associated log.
- `events`: bounded live replay buffer; tool job output is also stored on disk with 5 MB rotation and three backup generations.

Legacy `scan_results` databases receive an additive migration. Before the old duplicate-prone rows are consolidated, the original SQLite database is backed up to `session.legacy-backup.sqlite3`. Original scan artifacts and Gowitness databases are retained. Do not run old and new controllers simultaneously against one session.

Target files are derived exports, never the audit source of truth. Only open services on hosts currently marked up enter audit plans. A later explicit closed-port observation removes it from the active service list; an unscanned port remains previously observed, not silently declared closed. Current observations reflect import order. Source files, import digests and immutable normalized records retain provenance.

## Scan planning

`config.py` preserves the supplied menu text and IDs. A declarative profile contains arguments, phase, capture mode, required scripts and interface requirements. `core/scanner.py` owns targets, self-exclusions, output paths, reason reporting and progress reporting. It constructs argv lists, never shell command strings. Custom scan flags cannot override managed output files, target input or exclusions.

The audit planner groups known open ports by host and transport. TCP, UDP and SCTP are separate jobs, run sequentially. Scan 52 explicitly expands to all ports and requires confirmation (or `--expand-all-ports` in batch mode). Host-only discovery must be followed by port discovery before an audit is possible. Industrial-service ports are omitted from automatic audits unless the instructor explicitly includes them.

Dumpcap packet capture starts before each network job after it confirms its capture file is ready. Numeric Nmap port lists become transport-specific BPF terms with ICMP feedback. Ranges use `net`, IP lists use grouped `host` expressions, and idle scans capture the zombie exchange. Discovery protocols use ARP, DNS, ICMPv6, EIGRP or OSPF filters as appropriate. RPC/NFS and multi-step external tools use a target-scoped filter so dynamic service ports remain visible. A failed capture is never silently replaced with an unrestricted capture.

Process groups, including helpers, are terminated and reaped on completion, error, timeout or Ctrl+C. Nmap failure is stored as failure even when usable partial artifacts can still be imported. The dashboard stays up after scans; Ctrl+C or `q` closes the controller and viewer server.

## Evidence and teaching

OS match names from Nmap take precedence. TTL estimates remain labeled; absent TTL stays unknown. Hop distance and topology edges require Nmap distance/traceroute evidence. TCP window sizes are not combined into a confident OS guess: raw fingerprint evidence needs more context than the proposed lookup table provides.

The domain-controller highlight follows the specification's **complete set of configured TCP ports**, rather than tagging a host from one matching port. This remains an indicator, not proof of an AD domain controller. SearchSploit output is an exploit reference, not verified vulnerability evidence.

Course JSON profiles contain scan settings; CLI arguments take precedence. Comparisons report added, removed and changed open-service observations between saved sessions. A removed observation does not prove a service was remediated unless the two scans had equivalent coverage. PCAP analysis runs offline and produces downloadable protocol/conversation reports.

## Adding an adapter

1. Add a module under `modules/` with the requested project/module/purpose header and input/output footer.
2. Select applicability using exact address/port/protocol records from `modules.tools.services`.
3. Build an argv list. Invoke `modules.tools.execute`, supplying target capture scope, timeout, and a redacted display command where appropriate.
4. Save a concise artifact report using `artifact_output`.
5. Add a terminal offer in `external_tools`; never add a dashboard execution route.
6. Add a fixture/stub test for eligibility, arguments and output interpretation. Test the actual tool/version in the Kali lab before calling it validated.

An optional adapter's absence or failure should not corrupt the session or stop other independent work. The existing adapters keep individual public entry functions for troubleshooting and extension.

## Port uncertainty in the viewer

The dashboard displays `open`, `open|filtered`, `filtered`, and `unfiltered` observations with an explicit State column, Reason and a persistent state filter. Confirmed-open totals, most-services ranking, target exports, domain-controller matching, audit planning and external-tool handoffs continue to use confirmed `open` observations only. A no-response reason never overrides Nmap's state. Verification copy commands for uncertain ports omit version detection and NSE service scripts.

Exact Nmap XML `extraports` port lists are retained. A single anonymous summary can be reconstructed only when a single-transport `scaninfo` scope and explicit-port complement match its count exactly. Ambiguous aggregate counts do not invent port identities. The importer version is recorded; old imports can be enriched on resume without replacing a newer existing port observation. Local-address detection and exclusions are unchanged.

## Routed capture interfaces and lifecycle evidence

An ordinary routed scan defaults to Linux's `any` capture interface while retaining its target BPF scope. This captures SYN/raw traffic and TCP-connect/version/script traffic on whichever NIC the OS route selects. An explicit physical `--interface` is checked against bounded local `ip -j route get` samples before a network job; a known mismatch stops the job with a clear diagnostic. Local/broadcast/multicast profiles keep a physical interface. These checks do not change kernel routing, local address detection, self-exclusions or Nmap target scope.

Detailed discovery profiles 40–46 retain all target-scoped traffic, including ARP and Nmap host-discovery probes outside the service-port list. Audit jobs retain their per-host/per-transport port filters and ICMP feedback. `any` does not mean unrestricted capture: BPF target scope remains active.

Dumpcap must emit its `File:` readiness message and create the capture file before the scan starts. Shutdown sends SIGINT and waits for graceful completion, with process-group cleanup as a fallback. Each `<stem>_capture.json` records the selected interface, BPF, route samples, packet count, status and any forced stop. Empty/unverified captures raise visible events. If a completed Nmap job confirms open services but capture reports zero packets, scan artifacts are retained and the overall operation reports a capture failure rather than full success.

## Specialized evidence

`core/zombies.py` stores candidate observations and append-only fresh checks in `zombie_checks`, independently of assessment target exports. XML parser version 3 enriches older imports without overwriting newer assessment state. `modules/zombie.py` validates selected candidates before idle scans.

`modules/firewalker.py` coordinates captured route/port preflight and conditional Firewalk execution, retaining JSON/text reports in `specialized_reports` plus raw Nmap evidence. Gateway selection is report focus; the Nmap engine probes the measured path. The viewer exposes both evidence types through read-only snapshot fields and existing contained artifact downloads.
