# Scan 61: routed Firewalk exercise

Firewalk uses TTL-limited probes and router feedback to infer possible filtering points. It requires a target behind an intermediate router, raw-socket privileges, Nmap with the `firewalk` NSE script, and dumpcap when capture is enabled. A directly connected VM target is not a useful gateway-filtering exercise.

## Terminal workflow

1. Enter one literal IPv4 or IPv6 target address. Local scanner addresses remain excluded.
2. Protocol selection is **TCP**, **UDP**, or **both**, with explicit port lists. The TCP default is 21,22,23,25,80,443,445,3389; UDP defaults to 53,123,161,500.
3. Optionally tune the script: maximum eligible ports per protocol (default 7, -1 means all), retries (1), parallel probes (4), probe timeout (1000 ms) and receive timeout (1000 ms). Inputs have bounded ranges and are validated before execution.
4. A captured preflight performs the chosen port scan and traceroute. The path must reach the target and identify at least one intermediate router. Choose an observed gateway or all gateways. Batch mode defaults to the last observed intermediate gateway.
5. TTL probing runs only if preflight finds unanswered filtered TCP or open|filtered UDP ports. The final run retains a new port/route observation and the NSE report. Missing evidence, changed routes and absent script output are reported explicitly.

**Gateway selection focuses the report.** Nmap's Firewalk NSE script has no gateway-only parameter; its probes cover the measured route. The selected gateway is highlighted while all returned blocking rows remain visible. This workflow does not force routing through a selected gateway.

```bash
sudo .venv/bin/python main.py --customer CourseLab --interface any \
  --scan 61 --targets 203.0.113.10 --firewalk-protocol both \
  --firewalk-tcp-ports 22,443 --firewalk-udp-ports 53,161 \
  --firewalk-gateway all --firewalk-max-ports 7 \
  --firewalk-retries 1 --firewalk-parallel 4 \
  --firewalk-probe-ms 1000 --firewalk-recv-ms 1000 --non-interactive
```

Substitute your routed training target. Use `--dry-run` to inspect both command stages and the capture filter without launching probes. Interactive `b` and `q` at gateway selection retain the completed preflight and a cancelled report. Ctrl+C interrupts an active job; existing evidence remains.

## Capture scope

Captures retain target traffic plus ICMP Time Exceeded/Destination Unreachable messages that quote the target destination, including messages whose outer source is an intermediate router. IPv4 and ordinary IPv6 quoted headers are supported. Unrelated quoted destinations are excluded. IPv6 extension-header chains inside error quotations may need manual capture analysis; no claim of arbitrary extension-chain traversal is made.

The shared route-aware collector defaults to Linux `any`. An explicitly selected physical NIC must match the target route. Capture startup, drain, packet counts and errors use the same diagnostics as other scans. Empty/failed/unverified required captures prevent a successful workflow status; Nmap artifacts are still preserved. `--no-capture` explicitly disables this requirement.

## Interpret the report

The **Firewalk reports** dashboard tab shows status, target, gateway focus, possible blocking rows by protocol/hop, measured path, probe settings, warnings, raw NSE output and downloadable JSON/XML evidence. JSON and text report artifacts are retained per invocation. The dashboard displays the latest 20 reports; older artifacts and database records remain.

- `completed`: Nmap returned a blocking table; these are possible blocking inferences for the probed subset.
- `no_blocking_inferred`: Nmap reported `None found`; this does not establish unrestricted forwarding.
- `no_eligible_ports`: preflight found no eligible unanswered ports; TTL probing was skipped.
- `inconclusive`: route prerequisites, final route consistency or script evidence were insufficient.
- `error` / `cancelled`: execution/capture failed or the instructor left the workflow.

A filtered port is not a confirmed open service. These reports neither verify firewall rules nor establish that a service is reachable. Compare router/firewall configuration, packet evidence and the raw Nmap output during teaching.
