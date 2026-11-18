# First functional refactor

The supplied design takes precedence over the previous GitHub behavior. Terminal control, shared LAN viewing, Kali/Debian tooling, and menu IDs are the release baseline.

## Implemented across the five milestones

1. **Foundation:** persistent session manifests, collision-resistant artifacts, additive database migration, import provenance, exact port/protocol identities, process groups, exit-status handling and tool diagnostics.
2. **Discovery/audit:** all specified menu IDs, custom flags, scoped BPF generation, named NSE preflight, per-host/per-transport audits, XML/GNMAP import and recovery, target/OS/service exports and fresh zombie suitability validation.
3. **Viewer dashboard:** offline dark/green design, shared authentication, live terminal events, current state and heartbeat, preserved sorting/search/pagination, service-specific copy commands, host inventory, evidence inspection, artifacts, screenshots and execution/import history.
4. **Adapters:** Gowitness 3.x command builder, SearchSploit reference reports, SMB/NetBIOS enumeration, explicit guest share download, RPC/NFS inventory and read-only export inspection, community verification/SNMP inventory, bounded optional web content discovery.
5. **Teaching:** saved course profiles, session comparison artifacts, measured traceroute visualization, PCAP analysis recipes and offline protocol summaries.

## Deliberate differences and remaining lab validation

- Host-only scans cannot magically provide a discovered-port audit scope. Run 40–46 next when no confirmed open ports exist.
- Ports marked `open|filtered` are retained as observations but excluded from confirmed-open totals, service handoffs and audits.
- TCP, UDP and SCTP audit jobs are separate even for the same host. This prevents protocol confusion and produces explicit per-job evidence.
- The supplied labels for 70 and 71 are retained verbatim, but 71 implements a real Nmap idle scan using a verified zombie candidate. It is not a duplicate decoy command. NULL/XMAS/FIN results still require interpretation appropriate to the target OS/firewall.
- Broadcast EIGRP/OSPF and IPv6 discovery are interface-scoped techniques. Replies can appear in pre-scan script output rather than structured `<host>` records; their raw output/artifacts are retained. Automatic conversion of all protocol-specific routing advertisements into inventory is not claimed.
- Greedy mode automates applicable **enumeration** offers. Share downloads and NFS mounting remain distinct explicit terminal actions; IPC$ is not treated as a normal downloadable file share. NFS inspection mounts read-only outside artifact traversal and always attempts unmount.
- Named, locally installed NSE scripts are checked rather than blindly executing misspelled examples. Profile 50 uses the specified `vuln,auth,default,discovery` script categories, full version checking and script tracing. A narrower audit can be selected with custom phase-2 flags; per-service copy suggestions use explicit script names.
- The topology is an observation graph, not a reconstructed physical network diagram. TTL-only evidence never creates a router edge or identifies Cisco equipment.
- Gowitness screenshots are shared through the authenticated gallery on port 8888. The standalone report UI on 8889 is opt-in and bound locally by the documented command.
- John/NTLM credential-capture chains, Yersinia flooding/STP/VTP/DTP demonstrations, and automated VLAN changes were exploratory “consider” items. They are not wired into routine discovery or auto-triggered by an OS/TTL guess. These need separate lab exercises and tool-specific integration work.
- Tool adapters other than Nmap were checked with command fixtures and stubs, **not with actual installed Kali tools or live lab targets** in this environment. Actual Gowitness/browser execution, SMB/SNMP/NFS compatibility, raw spoofing/idle/SCTP behavior and packet-capture permissions must be acceptance-tested on your Kali 2026.2 build.
- Execution logs rotate at 5 MB with three backup generations per job; the live SQLite event buffer is bounded. Dashboard logs also rotate at 5 MB. Nmap retains its original -oA artifacts. Overall artifact/PCAP disk usage remains instructor-managed. Very large target sets should be split into course-sized scopes.

## Validation

See `docs/VALIDATION.md` for exact checks and limits. A synthetic dashboard screenshot is included under `docs/images/`; it contains documentation-range addresses, not a real assessment.

## Capture startup compatibility fix

Live capture now invokes `dumpcap` directly, rather than `tshark`. This avoids loading Tshark protocol/dissector plugins, including incompatible optional plugins that can abort startup with undefined-symbol errors. Dependency diagnostics distinguish dumpcap capture from Tshark offline analysis. Root/raw-socket requirements for Nmap are unchanged. Regression tests cover failed startup, successful capture lifecycle and dependency selection; live interface permissions still require validation on the lab machine.

## Uncertain port observations and analysis readiness

The viewer now shows uncertain Nmap states alongside confirmed open ports, with separate counts, state/reason fields, filtering and verification-only copy commands. Exact grouped port evidence in XML is recovered where possible; counts alone do not become invented port IDs. Automatic service enumeration remains restricted to confirmed open ports. Local-IP detection and --exclude behavior are unchanged.

Offline recipes are generated from analysis-tool readiness. A detected Falco/undefined-symbol startup error withholds Tshark commands while capinfos and optional tcpdump remain available. The guide is refreshed on resume, uses downloaded filenames, and explains root-owned file access and zero-packet captures. This does not automatically repair or modify operating-system packages.

## Zombie menu labels and IPID compatibility

Scan 60 is labeled [N] because candidate discovery actively probes hosts and includes OS detection. Scan 05 now points operators to Scan 60 when they need a candidate. IPID parsing accepts actual NSE output `Incremental!`, native `Incremental`, and the optional debug probe-port suffix. It does not accept `Broken incremental!` or unrelated substring matches. This shared parser fix applies both to hunter exports and the pre-idle-scan validation.

Scan 60 still operates on the instructor-supplied scope; automatic OS-unknown selection, a terminal candidate picker and structured validation-failure reasons remain suggested workflow improvements, not completed behavior. Scan 05 still revalidates each selected candidate and retains its current open-probe-port requirement.

## Capture routing mismatch correction

A lab report confirmed successful Scan 42/50 traffic routed through eth1 while capture listened on eth0. Ordinary routed captures now default to Linux `any` within the existing target filter; explicit physical interface choices are checked against local routes. Local discovery keeps its physical NIC. Detailed discovery captures preserve target-scoped ARP, host discovery and service probes. Local-IP exclusions and target routing are unchanged.

The capture runner now waits for file readiness, drains dumpcap with SIGINT, records route/interface/filter/count diagnostics in per-job JSON, and visibly reports empty/unverified captures. An empty required capture alongside confirmed open Nmap results is an operation failure, while retaining all valid scan results. Validation includes real libpcap execution against SSH/Linux packets on Ethernet, Linux SLL and SLL2 formats, plus route/lifecycle regression tests.

## Explicit terminal navigation

Session commands now distinguish `b=back` from `q=exit`. Nested instructor prompts advertise both; `b` cancels the remaining prompted workflow and returns to the main scan-ID prompt, while `q` requests normal session shutdown and closes the viewer. Completed scans, imported evidence and artifacts are preserved. At the main menu `b` is a no-op/redraw. View-only sessions no longer advertise unavailable external-tool execution. Navigation is available at prompts; active process interruption still uses Ctrl+C. Non-interactive execution is unchanged.
