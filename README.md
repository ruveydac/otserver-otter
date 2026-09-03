<div align="center">

# OTserver Otter

### Read-only OT discovery for the [OTserver inventory](https://github.com/ruveydac/OTserver)

Native ARP · PROFINET DCP · S7 · EtherNet/IP · BACnet · FINS · Fox · OPC UA · SNMP · LLDP

[![Website](https://img.shields.io/badge/otserver.org-111111?logo=firefoxbrowser&logoColor=white)](https://otserver.org)
[![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Platforms](https://img.shields.io/badge/Windows_%7C_Linux-0078D6?logo=windows&logoColor=white)](#quick-start)
[![OTserver](https://img.shields.io/badge/OTserver-Next.js-000000?logo=javascript&logoColor=white)](https://github.com/ruveydac/OTserver)
[![AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENCE.md)

[Quick start](#quick-start) · [Protocols](#protocols-and-safety) · [Configuration](#configuration-and-direct-import) · [Lab](#virtual-ot-lab) · [Development](#development)

</div>

---

OTserver Otter is a cross-platform Rust CLI (with an optional GUI) built specifically for identifying
industrial devices through fixed, read-only protocol requests. It discovers IPv4/MAC pairs with ARP
and directly queries PROFINET DCP, S7, EtherNet/IP, BACnet, Omron FINS, Niagara Fox, OPC UA, and
optional SNMP/LLDP. It collects structured evidence—not just a flat host list—and exports
observations, interfaces, ports, and topology through the schema-version-2 `otserver-scan` contract
understood directly by [OTserver](https://github.com/ruveydac/OTserver).

Windows uses native IP Helper for active ARP, Npcap for active PROFINET DCP, and Microsoft pktmon
as a passive fallback. Linux uses native `AF_PACKET` raw sockets. No TAP adapter or Windows Network
Bridge is used or modified.

## What you get

- **Native protocol identity** — Fixed queries designed to retrieve device identity without
  configuration changes, vulnerability scripts, or exploit behavior.
- **Evidence-preserving output** — Per-protocol observations and raw source data alongside
  normalized devices, instead of collapsing a scan into one guessed record.
- **Topology-aware collection** — LLDP, SNMP, and PROFINET link evidence, network interfaces, and
  ports in a validated JSON export.
- **Quality-aware by design** — Each observation reaches the importer with its source quality, so
  stronger evidence improves the inventory without overwriting human edits.
- **Predictable failure handling** — Valid partial results with warnings when individual probes
  fail; malformed and unsolicited responses are rejected.
- **Direct import** — Send a completed scan straight to OTserver's REST importer with your site
  permissions, keeping the local JSON file.

## Quick start

Otter requires `--ack-authorized` before every scan. Only scan networks you own or are authorized
to assess.

### Linux

```bash
cargo build --release
sudo ./target/release/otserver-otter doctor
sudo ./target/release/otserver-otter interfaces
sudo ./target/release/otserver-otter scan \
  --target 192.168.1.0/24 \
  --interface eth0 \
  --source-mac 00:11:22:33:44:55 \
  --output ./scan.otserver.json \
  --ack-authorized
```

Linux Ethernet discovery uses a native `AF_PACKET` raw socket and therefore needs root or
`CAP_NET_RAW`.

#### Raspberry Pi

Tagged releases include `otserver-otter-linux-aarch64.tar.gz` for Raspberry Pi 3, 4, 5, and
Zero 2 W running 64-bit Raspberry Pi OS Bookworm or newer. This headless build omits the GUI; run a
CLI subcommand such as `doctor`, `interfaces`, or `scan`. It requires the Raspberry Pi OS `libssl3`
package and the same root or `CAP_NET_RAW` access as other Linux builds.

Release builds expose the triggering Git tag as their CLI, GUI, scan-export, and Windows Explorer
version. Local builds use the nearest reachable Git tag; source archives without Git metadata fall
back to the Cargo package version. `OTTER_BUILD_VERSION` can explicitly override this value for a
reproducible external build.

To build the headless scanner natively instead:

```bash
cargo build --locked --release --no-default-features
```

### Windows

```powershell
cargo build --release --target x86_64-pc-windows-msvc
.\target\x86_64-pc-windows-msvc\release\otserver-otter.exe doctor
.\target\x86_64-pc-windows-msvc\release\otserver-otter.exe interfaces
.\target\x86_64-pc-windows-msvc\release\otserver-otter.exe scan `
  --target 192.168.1.0/24 `
  --interface '<interface name or GUID>' `
  --source-mac 00:11:22:33:44:55 `
  --no-bacnet `
  --output .\scan.otserver.json `
  --ack-authorized
```

Windows ARP discovery needs no additional driver. Active PROFINET discovery requires a separately
installed [Npcap](https://npcap.com/#download). If Npcap is unavailable, the scanner uses built-in
pktmon as a passive fallback. Pktmon requires Administrator rights and cannot transmit DCP Identify
frames.

Npcap installation is always an explicit user action and never occurs during a scan. The scanner
loads `%SystemRoot%\System32\Npcap\Packet.dll` directly, matches the selected physical interface by
GUID, transmits DCP Identify, and captures only PROFINET Ethernet frames. Npcap's free license permits
up to five installations but not redistribution; larger or bundled deployments require an appropriate
Npcap OEM license.

Active DCP verifies that the configured source MAC belongs to the selected physical interface before
opening the selected Npcap adapter. Identify-All is sent once with an engineering-tool response
delay factor so device replies are spread over the capture window instead of creating a synchronized
response burst.

The Windows executable exposes its build Git tag in Explorer file properties and in the GUI.
Starting the GUI detaches its console window; CLI commands keep normal terminal input and output.

Tagged GitHub releases also publish signed SLSA provenance covering the SHA-256 digest of every
Linux archive and Windows executable. This lets consumers verify that an artifact was produced by
this repository's release workflow and was not modified afterward. SLSA provenance is separate from
Windows Authenticode signing; an Authenticode publisher signature still requires a trusted
code-signing certificate or managed signing service.

Validate an export before uploading it:

```powershell
.\otserver-otter.exe validate .\scan.otserver.json
```

## Protocols and safety

The scanner sends PROFINET DCP Identify, read-only SNMP requests, and fixed read-only identity
requests for S7, EtherNet/IP, BACnet, Omron FINS, Niagara Fox, and OPC UA. It never runs SNMP SET,
DCP Set, brute-force, exploit, vulnerability, or Modbus requests.

All discovery protocols are enabled by default. Disable individual protocols on the CLI with
`--no-arp`, `--no-profinet`, `--no-s7`, `--no-enip`, `--no-bacnet`, `--no-fins`, `--no-fox`,
`--no-opcua`, or `--no-snmp` and `--no-lldp`. SNMP inventory and LLDP topology queries share the
same SNMP settings but can be enabled independently. The GUI exposes the same choices as
highlighted on/off toggle buttons.

Exit code `0` means every scan completed, `2` means at least one valid output contains partial
failures, and `1` means a configuration, scan, or upload failed. A multi-configuration run continues
after failures and reports exit code `1` after attempting the remaining configurations. Stopping a
running scan writes a valid partial export containing all results collected before cancellation.

SNMP uses bounded, read-only queries covering MIB-II (RFC 1213) system and interface identity,
LLDP-MIB topology (IEEE 802.1AB) with the LLDP-EXT-DOT1, LLDP-EXT-DOT3, and LLDP-EXT-PNO
extensions (IEEE 802.1AB / IEC 61158-6-10), MRP media-redundancy monitoring (IEC 62439-2),
IF-MIB/IP-MIB interfaces, ENTITY-MIB components, BRIDGE/Q-BRIDGE ports and VLANs, and the generic
Siemens AUTOMATION-SYSTEM-MIB identity scalars. It probes configured IPv4 targets even when Layer 2
discovery cannot see them, but creates an asset only after obtaining a valid MAC from an interface,
bridge, or LLDP chassis identity. Forwarding-table MACs are port evidence only and never asset
identities.

OPC UA discovery connects to ports 4840, 4841, and 48400 by default (configurable via `opcuaPorts`).
The scanner prefers anonymous authentication and reads only asset identification, health, and
location variables; it never writes values or calls methods that modify server state.

### GUI

The GUI keeps a selectable, auto-scrolling log panel to the right of its configuration, with an
always-visible clear action, scan status, and configuration-save result. The output field accepts a
filename directly or opens the native save-file picker. When `otter.json` contains multiple
configurations, the GUI can run the selected configuration or run all configurations sequentially;
**Stop Scan** stops the current scan, writes its partial output when possible, and skips all pending
entries.

The scan log records one entry per probed IP and protocol, for example
`[12:43] 192.168.1.10 Protocol snmp Success`. Every log line is timestamped. SNMP attempts also show
the version and sanitized security choices, such as
`[12:43] 192.168.1.10 SNMP attempt version=3 security=authPriv authentication=SHA-256 encryption=AES-128 Success`.

### SNMP settings

SNMP settings and credentials live in the `snmp` block of `otter.json` and are fully editable in the
GUI. The `snmp` value is a single credential object or a list of credentials; a list is tried in
order per target until one succeeds, so one configuration can combine an SNMPv3 user with several
SNMPv1/v2c communities. Without any settings, SNMPv2c with the community `public` is used, so SNMP
never blocks a scan. Set `version` to `1` for a legacy SNMPv1 agent. For SNMPv3 set `version` to `3`
plus `username`, optional `contextName`, and the `authProtocol`/`authPassword` and
`privacyProtocol`/`privacyPassword` pairs. Credentials are stored in plaintext in `otter.json`; keep
the file out of source control and restrict its permissions. Credentials are never written to logs
or scan exports. Set `version` to `auto` to opt into fallback: the scanner tries SNMPv3 first when a
username is configured, then SNMPv2c, then SNMPv1, stopping at the first successful version.
Explicit `1`, `2c`, and `3` selections never fall back. The GUI manages the list in a table of every
active credential in try order, with **Remove**, **Add Credential**, and masked passwords.

SNMPv3 settings may include an optional `contextName`. Most physical devices use the default empty
context and can omit it; simulators and partitioned agents may require it.

### OPC UA settings

If an OPC UA server requires username authentication, set `opcuaCredentials` in the config — a single
`{ "username", "password" }` object or a list of them. Anonymous access is always tried first; the
configured credentials are tried top to bottom only when it fails. The legacy single
`opcuaUsername`/`opcuaPassword` pair remains supported. The GUI shows the same credential table as
for SNMP: rows in try order with **Remove**, **Add Credential**, and the edit fields below. Passwords
travel unencrypted because the scanner uses SecurityPolicy None, and are never written to logs or
scan exports.

## Configuration and direct import

Place an optional `otter.json` beside the executable to provide scan defaults and an OTserver
destination. Existing `otscanner.json` files are loaded when `otter.json` is absent. The existing
single-object form remains supported:

```json
{
  "targets": ["192.168.1.0/24"],
  "interface": "eth0",
  "sourceMac": "00:11:22:33:44:55",
  "output": "scan.otserver.json",
  "snmp": {
    "version": "2c",
    "community": "public"
  },
  "noArp": false,
  "noProfinet": false,
  "noS7": false,
  "noEnip": false,
  "noBacnet": false,
  "noFins": false,
  "noFox": false,
  "noOpcua": false,
  "opcuaPorts": [4840, 4841, 48400],
  "opcuaCredentials": [{ "username": "inventory", "password": "..." }],
  "noSnmp": false,
  "noLldp": false,
  "serverUrl": "https://otserver.example",
  "site": "PAYLOAD_SITE_ID",
  "apiKey": "PAYLOAD_USER_API_KEY"
}
```

The root can instead be an array of configurations. Every array entry requires a unique, non-empty
`name`, and resolved output paths must be unique so one scan cannot overwrite another:

```json
[
  {
    "name": "Line A",
    "targets": ["192.168.1.0/24"],
    "interface": "eth0",
    "sourceMac": "00:11:22:33:44:55",
    "output": "line-a.otserver.json"
  },
  {
    "name": "Line B",
    "targets": ["192.168.2.0/24"],
    "interface": "eth1",
    "sourceMac": "00:11:22:33:44:66",
    "output": "line-b.otserver.json"
  }
]
```

The GUI exposes **Add Configuration**, a configuration selector, **Run Selected**, and **Run All**.
Adding a configuration clones the selected settings, assigns a unique name and output filename, and
converts a single-object file to the array form when necessary. The CLI `scan` command runs array
entries sequentially in file order and continues with later entries after a configuration, scan, or
upload failure.

An SNMPv3 block looks like this instead:

```json
{
  "snmp": {
    "version": "3",
    "username": "inventory",
    "contextName": "optional-snmp-context",
    "authProtocol": "sha256",
    "authPassword": "...",
    "privacyProtocol": "aes128",
    "privacyPassword": "..."
  }
}
```

To try several credentials in one scan, use a list. Entries are probed in order per target and
duplicate entries are skipped:

```json
{
  "snmp": [
    {
      "version": "3",
      "username": "inventory",
      "authProtocol": "sha256",
      "authPassword": "..."
    },
    { "version": "2c", "community": "public" },
    { "version": "2c", "community": "legacy-private" }
  ]
}
```

Command-line values override every selected file entry, and `OTSERVER_API_KEY` overrides every
entry's `apiKey`. A shared `--output` override therefore cannot be used for a multi-entry run because
the resolved paths would collide. Relative paths are resolved from the current working directory.
The config contains credentials in plaintext; keep it out of source control and restrict its
permissions (for example, `chmod 600 otter.json`). The safer automation setup omits `apiKey`
from the file and supplies `OTSERVER_API_KEY` through the process environment.

When `serverUrl`, `site`, and an API key are present, `scan` writes and validates the local JSON and
then posts it to OTserver's REST API. The local file remains available if the upload fails. The site
must be its Payload document ID, and the API key user must have read/write access there. Explicit
flags can also select the destination:

```bash
OTSERVER_API_KEY='...' otserver-otter scan \
  --target 192.168.1.0/24 \
  --interface eth0 \
  --source-mac 00:11:22:33:44:55 \
  --server-url https://otserver.example \
  --site PAYLOAD_SITE_ID \
  --ack-authorized
```

`--ack-authorized` is intentionally never read from configuration and remains mandatory for every
scan.

## Virtual OT lab

The Docker lab exercises the complete Linux scanner against deterministic virtual devices for ARP,
PROFINET DCP, S7, EtherNet/IP, BACnet/IP, Omron FINS, Niagara Fox, OPC UA, SNMPv2c, SNMPv3, and LLDP:

```bash
./lab/test.sh
```

It requires Linux containers, Docker Engine with Compose, and permission to use the Docker daemon.
The scanner and Siemens containers receive only `NET_RAW`; the lab does not use host networking or
publish protocol ports. Windows developers can run the same command through Docker Desktop with
WSL2. Scan JSON and Compose logs are retained under `lab/artifacts/`.

To exercise the native Windows executable against the Docker Desktop responders, run PowerShell on
the Windows host:

```powershell
.\lab\test-windows.ps1
```

The Windows version is a protocol-client smoke test, not a multi-device discovery test. It binds the
responder ports only to Docker/WSL's host-only Hyper-V adapter and runs the real `.exe` against that
single host-routed endpoint. Consequently, Windows ARP sees the Hyper-V adapter's MAC and all
forwarded protocol responses belong to that one temporary identity; Docker's internal container
MACs are not visible to the Windows host. The importable scan is deleted after validation and only a
plain-text summary and Compose log are retained.

This smoke test covers Windows ARP, S7, EtherNet/IP, BACnet, FINS, Fox, OPC UA, SNMP, and LLDP
client paths. It does not verify distinct device MAC correlation. Docker Desktop also does not bridge
raw Ethernet frames between its Linux bridge and a Windows capture driver, so the harness disables
PROFINET DCP. Active Windows DCP and multi-device MAC discovery require physical Layer-2 test devices
or a dedicated external Layer-2 test interface.

Images use pinned Snap7 and SNMP Simulator packages plus checksum-pinned OpENer and BACnet Stack
sources; the repository's small FINS and Fox responders implement only the fixed read-only identity
requests sent by this scanner. The OPC UA responder uses the maintained asyncua (opcua-asyncio)
Python stack.

## Development

Run the checks before committing:

```bash
cargo fmt -- --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo llvm-cov --lib --fail-under-lines 90 --summary-only -- --test-threads=1
./lab/test.sh
```

Scanner branch, loop, and parser logic needs a focused Rust unit test. Protocol interoperability
belongs in the Docker lab. The canonical wire contract is
[`contracts/otserver-scan-v2.schema.json`](contracts/otserver-scan-v2.schema.json); a contract
change requires coordinated updates in the [OTserver](https://github.com/ruveydac/OTserver) importer.

## License

OTserver Otter is dual-licensed with OTserver: it is available under
[GNU AGPLv3](LICENCE.md), or under a commercial license for proprietary use
without AGPLv3 copyleft obligations. For commercial licensing, enterprise
features, or managed hosting, visit [otserver.org/enterprise](https://otserver.org/enterprise/).

The scanner and the detection needed to find assets and device capabilities
will remain 100% open source. Optional enterprise add-ons, such as SSO
integrations or customized dashboards, do not restrict the open-source core.
