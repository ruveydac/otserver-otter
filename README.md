# OTserver Otter

Read-only discovery of industrial devices for [OTserver](https://github.com/ruveydac/OTserver).

Otter is a Windows and Linux discovery tool with a command-line interface and an optional GUI.
It collects device identities, firmware, network interfaces, and topology, then exports JSON
that you can import into OTserver. It can also upload results directly or run as a centrally
managed scanner.

[Website](https://otserver.org) · [Download](https://github.com/ruveydac/otserver-otter/releases) · [Quick start](#quick-start) · [License](#license)

## What it discovers

Otter uses ARP, PROFINET, S7, EtherNet/IP, BACnet, Omron FINS, Niagara Fox, DNP3, IEC 61850,
NetBIOS, SMB, RPC, OPC UA, SNMP, and LLDP to collect identity and network evidence.
Results retain per-protocol observations and warnings, including partial results when individual
probes fail.

Discovery uses fixed, read-only requests. Otter does not change device configuration, run exploits,
or perform active vulnerability checks. Only scan networks you own or are authorized to assess.
Read-only discovery still generates network traffic; assess its suitability for your network.

## Quick start

Download the build for your platform from the
[releases page](https://github.com/ruveydac/otserver-otter/releases) and extract it.
Use `doctor` to check your setup and `interfaces` to find the adapter name and MAC address.

### Linux

Ethernet discovery requires root or `CAP_NET_RAW`:

```bash
sudo ./otserver-otter doctor
sudo ./otserver-otter interfaces
sudo ./otserver-otter scan \
  --target 192.168.1.0/24 \
  --interface eth0 \
  --source-mac 00:11:22:33:44:55 \
  --output ./scan.otserver.json \
  --ack-authorized
```

Replace the example network, interface, and MAC with your own values.
Raspberry Pi releases support 64-bit Raspberry Pi OS Bookworm or newer and require `libssl3`.
These builds are command-line only.

### Windows

```powershell
.\otserver-otter.exe doctor
.\otserver-otter.exe interfaces
.\otserver-otter.exe scan `
  --target 192.168.1.0/24 `
  --interface '<interface name or GUID>' `
  --source-mac 00:11:22:33:44:55 `
  --output .\scan.otserver.json `
  --ack-authorized
```

Windows ARP discovery needs no additional driver. Active PROFINET DCP requires a separate
[Npcap installation](https://npcap.com/#download). Without it, Otter uses Windows pktmon for
passive capture, which requires Administrator rights and cannot send DCP Identify requests.

### Use the results

Import `scan.otserver.json` into OTserver, selecting the site where the devices belong.
Every scan requires `--ack-authorized`. Run `scan --help` for protocol switches and other options.

## Configuration and managed scans

An optional `otter.json` beside the executable stores scan settings and multiple configurations.
The GUI can edit these settings and run one or all configurations. Local credentials are stored
in plaintext in that file; restrict its permissions and keep it out of source control.

For central management, enroll the scanner using a token from OTserver:

```bash
otserver-otter controller --server-url https://otserver.example \
  --enroll --ack-authorized
```

Enter the enrollment token at the prompt. On later starts, omit `--enroll` to reuse the saved
credential. Configure and schedule scans in OTserver. Remote controllers require HTTPS;
HTTP is supported only for loopback addresses.

See [AGENTS.md](AGENTS.md) for configuration examples, direct uploads, controller operation,
platform details, and troubleshooting constraints.

## Development

Build from source with Rust:

```bash
cargo build --locked --release
```

For a headless build, add `--no-default-features`.
See [AGENTS.md](AGENTS.md) for protocol rules, export-contract requirements, test commands,
and the virtual OT lab.

## License

OTserver Otter is available under [GNU AGPLv3](LICENCE.md) or a commercial license for proprietary
use without AGPLv3 copyleft obligations. For commercial licensing, enterprise features, or managed
hosting, visit [otserver.org/enterprise](https://otserver.org/enterprise/).

The scanner and detection needed to find assets and device capabilities will remain open source.
Optional enterprise add-ons do not restrict the open-source core.
