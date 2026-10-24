<div align="center">

# OTserver Otter

### Read-only OT discovery for the [OTserver inventory](https://github.com/ruveydac/OTserver)

Native ARP · PROFINET DCP · S7 · EtherNet/IP · BACnet · FINS · Beckhoff ADS · Fox · DNP3 · IEC 61850 · NetBIOS · SMB · RPC · HTTP/HTTPS · OPC UA · SNMP · LLDP

[![Website](https://img.shields.io/badge/otserver.org-111111?logo=firefoxbrowser&logoColor=white)](https://otserver.org)
[![codecov](https://codecov.io/gh/ruveydac/OTserver-otter/graph/badge.svg)](https://codecov.io/gh/ruveydac/OTserver-otter)
[![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Platforms](https://img.shields.io/badge/Windows_%7C_Linux-0078D6?logo=windows&logoColor=white)](#quick-start)
[![OTserver](https://img.shields.io/badge/OTserver-Next.js-000000?logo=javascript&logoColor=white)](https://github.com/ruveydac/OTserver)
[![AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENCE.md)

[Quick start](#quick-start) · [Protocols](#what-it-discovers) · [Configuration](#configuration-and-managed-scans) · [Development](#development)

</div>

---

Otter is a Windows and Linux discovery tool with a command-line interface and an optional GUI.
It collects device identities, firmware, network interfaces, and topology, then exports JSON
that you can import into OTserver. It can also upload results directly or run as a centrally
managed scanner.

## What it discovers

Otter uses ARP, PROFINET, S7, EtherNet/IP, BACnet, Omron FINS, Beckhoff ADS, Niagara Fox, DNP3,
IEC 61850, NetBIOS, SMB, RPC, HTTP/HTTPS, OPC UA, SNMP, and LLDP to collect identity and network
evidence.

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

Windows ARP discovery uses [Npcap](https://npcap.com/#download) when it is available on the selected
adapter, sending up to 35 requests/s while collecting replies.
Active PROFINET DCP and PNIO I&M reads also require Npcap. Without it, Otter uses Windows pktmon for
passive capture, which requires Administrator rights and cannot send DCP Identify or PNIO requests.
Skipped targets and failed records appear in the scan warnings; successful records remain in the JSON.

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

### Install the controller in the background

Run as your normal user. To enroll and install in one step:

```bash
./otserver-otter controller --server-url https://otserver.example \
  --enroll --install --ack-authorized
```

For an already enrolled scanner, run `otserver-otter controller --install --ack-authorized`.
The saved URL and connection settings are reused. Installation starts the controller and exits;
the background process runs only managed scans assigned by OTserver.

In the GUI, use **OTserver controller → Enroll**, confirm authorization, and enter the controller URL
and single-use token. After enrollment, select **Install controller** and complete any OS prompt.
You can close the GUI afterward. The GUI's local scan controls save local JSON only; API-key direct
uploads remain available through CLI/configuration.

Stop the current controller before changing its installation or re-enrolling, so an active scan is
not interrupted. On Linux, use `systemctl --user stop otserver-otter-controller.service`; inspect
logs with `journalctl --user -u otserver-otter-controller.service`. On Windows, select the task in
Task Scheduler and choose **End**. Retry installation after a cancelled prompt or setup failure;
enrollment and retained exports are kept.

To disable automatic startup, use `systemctl --user disable --now otserver-otter-controller.service`
on Linux, or disable/delete the task in Windows Task Scheduler. Linux lingering is account-wide;
disable it with `loginctl disable-linger` only if no other user service needs it.

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
OTserver and OTserver Otter are dual-licensed:

GNU Affero General Public License v3.
A commercial license for enterprises, SaaS providers, and organizations integrating OTserver.
The open-source core will remain open source, including the scanner, detection needed to find assets and device capabilities, and base asset-management features. Optional proprietary add-ons, such as SSO integrations or customized dashboards, do not replace or restrict that core.

For commercial licensing, SLA support, or enterprise features, visit otserver.org/enterprise.
OTserver Otter is available under [GNU AGPLv3](LICENCE.md) or a commercial license for proprietary
use without AGPLv3 copyleft obligations. For commercial licensing, enterprise features, or managed
hosting, visit [otserver.org/enterprise](https://otserver.org/enterprise/).

The scanner and detection needed to find assets and device capabilities will remain open source.
Optional enterprise add-ons do not restrict the open-source core.
