# Tools and installation

The application requires **Python 3.11 or newer** on Linux. Kali 2026.2 and custom Debian builds should provide these executable names in the instructor process's `PATH`.

| Capability | Executables | Typical Kali/Debian package |
|---|---|---|
| Python environment | `python3`, venv/pip | `python3`, `python3-venv` |
| Scan engine | `nmap` | `nmap` |
| Live packet capture | `dumpcap` | `wireshark-common` |
| Offline packet inspection | `tshark`, `capinfos` | `tshark`, `wireshark-common` |
| Basic offline packet preview | `tcpdump` | `tcpdump` (optional fallback) |
| Interface discovery | `ip` | `iproute2` |
| Web screenshots | `gowitness`, compatible Chrome/Chromium | `gowitness`, `chromium` |
| Exploit reference lookup | `searchsploit` | `exploitdb` on Kali |
| SMB/NetBIOS enumeration | `enum4linux` and its Samba dependencies | `enum4linux`, `smbclient` |
| Guest share download | `smbget` | `smbclient` on Kali; verify packaging on your build |
| RPC/NFS discovery | `rpcinfo`, `showmount` | `rpcbind`, `nfs-common` |
| Read-only NFS inspection | `mount`, `umount`, NFS client support | `util-linux`, `nfs-common` |
| SNMP inventory | `snmp-check`, `onesixtyone` | `snmpcheck`, `onesixtyone` |
| SNMP community lists | local wordlist files | `seclists` optional |
| HTTP content discovery | `gobuster` | `gobuster` |
| Proxy-connected TCP profiles | `proxychains4` | `proxychains4` |

Only Nmap is needed for scans. Dumpcap and a usable interface are required when capture is enabled (the default). Other integrations are optional: unavailable tools are skipped with a diagnostic and do not erase scan results. Viewing or importing scans does not require Nmap, capture privileges or external tools.

Python runtime dependencies are Flask and Waitress, with their transitive dependencies. `requirements.txt` specifies supported version ranges; `requirements-lock.txt` records the exact environment used for validation. No JavaScript CDN, npm build step, external database or Redis service is needed.

Example core OS preparation on a Debian/Kali build you manage:

```bash
sudo apt install python3 python3-venv nmap tshark wireshark-common iproute2
./setup_scanRoids.sh
.venv/bin/python main.py --doctor
```

Install optional tools individually as needed. Package availability and naming can differ between Debian and Kali. The setup script intentionally installs only Python dependencies; it does not update your OS, download wordlists, or replace tool installations.

## Versions and privileges

- Nmap 7.95 was exercised against a temporary loopback HTTP service. The configured named NSE scripts were also checked with that version's `--script-help`. The application checks named scripts before executing a profile.
- Gowitness targets **3.x CLI syntax**: `gowitness scan nmap -f ... -s ... --write-db --write-db-uri ... --threads 4`. Its browser dependency must be usable under the account running the instructor controller. Browser sandbox requirements depend on the browser package and whether you run as root; configure your lab installation accordingly.
- Raw TCP/UDP/SCTP, OS detection, idle scans, spoofing and fragmentation generally require root. Invoke the virtualenv interpreter explicitly: `sudo .venv/bin/python main.py ...`. Do not rely on `sudo python` selecting your virtualenv.
- Tshark/dumpcap capture permissions must be configured for the chosen account, or use root. Capture startup failure stops the associated network job and records the error. `--no-capture` is an explicit alternative.
- Proxy mode requires a full TCP connect profile with `-sT -Pn -n`. Profiles 41/42/43/45 gain `-Pn` automatically in proxy mode. Use `--proxy-endpoint IP:port` for the first proxy when capture is enabled. Raw probes, UDP and SCTP are rejected. Some NSE scripts and external applications can create their own connections; proxy mode covers the Nmap invocation only.
- `onesixtyone` wordlists default to `/usr/share/doc/onesixtyone/dict.txt` or `/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt`. The terminal also accepts a custom path. A single community is written to a temporary file, as required by `-c`.

## LAN viewers

The dashboard listens on port **8888**, configurable with `--host` and `--port`. Permit this port through your lab firewall. It uses one shared viewer identity and a threaded Waitress server; scanning stays in the instructor terminal. Default credentials follow the requested design:

- Username: `operator`
- Password: `<customer>_<current-year>` (customer is the normalized session name)

Set `SCANROIDS_PASSWORD` in the instructor process's environment to override it. The password is printed only to the terminal, not the dashboard event stream. Direct LAN access uses HTTP; an existing TLS reverse proxy can provide HTTPS when required. The authenticated screenshot gallery is at `/gallery` on the same dashboard port. Gowitness's standalone report server is **not** exposed automatically on unauthenticated port 8889.

For local use of Gowitness's richer report UI, run it separately against the retained database:

```bash
cd /path/to/session/artifacts
gowitness report server --host 127.0.0.1 --port 8889 --db-uri sqlite://gowitness.sqlite3
```

The native dashboard gallery avoids separate authentication for remote viewers.

## Capture startup and Tshark plugin failures

Live captures use `dumpcap`, Wireshark's dedicated capture utility. Nmap may still require sudo for raw scan techniques, while dumpcap captures packets without loading Tshark's protocol/dissector plugins. A warning that an application is running as root is not by itself a capture failure.

A Tshark startup message such as `Couldn't load ... falco ... undefined symbol ...` instead indicates a plugin/shared-library compatibility problem. The live-capture path avoids that plugin dependency. Offline Tshark analysis still requires a consistent Wireshark/plugin/library installation; align those packages with the repositories used by your Kali/custom Debian build.

Check capture availability using `command -v dumpcap` and `sudo dumpcap -D`. Check the separate analysis installation with `tshark --version`. For non-root capture, Debian/Kali can configure dumpcap permissions through `sudo dpkg-reconfigure wireshark-common` and membership in the `wireshark` group; a new login is needed after group membership changes. This does not grant Nmap raw-socket privileges or access to root-owned session directories.

## Analysis recipes and root-owned captures

Tshark analysis is checked independently of live dumpcap capture. A plugin/undefined-symbol message is considered unhealthy even if `tshark --version` exits zero. The dashboard and regenerated capture guide withhold Tshark commands in that case, retain `capinfos`, and offer a bounded `tcpdump -nn -r ... -c 200` preview if installed. The startup check is cached for up to 30 seconds. No package is removed or changed automatically.

Use `dpkg -S '*falco-events.so'` to identify the owning package. Align the plugin and its Wireshark/gRPC/Abseil dependencies with a consistent Kali/Debian package set. If you do not need the optional Falco dissector, review removal of its owning package and dependencies through your package manager; do not delete arbitrary shared libraries. A successful dumpcap capture does not repair the separate Tshark analysis installation.

The generated guide uses downloaded filenames. Download a PCAP through the authenticated dashboard into your own account and analyze that copy. Reading the original root-owned capture directly may produce `Permission denied`; running sudo fixes access only, not a plugin/library mismatch. Avoid running protocol analysis as root simply to read a saved file.

If `capinfos` reports zero packets, there is nothing to decode regardless of display filter or plugin health. Check the scan target, capture interface and host filter. ScAnRoIdS still excludes local scanner IPs. Duplicate addresses between training VMs should be corrected in the lab network rather than disabling self-exclusion.
