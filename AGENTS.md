# Agent Guide

This file applies to the entire repository. Keep it current when a change alters a durable command,
contract, or safety boundary.

## Project Summary

OTserver Otter is a read-only Rust discovery CLI and GUI for Windows and Linux. It discovers OT
assets with native ARP, PROFINET DCP Identify and PNIO I&M record reads (EPM endpoint mapping,
bounded read requests, and DCE/RPC fragmentation/FACK handling), S7 identity, EtherNet/IP List
Identity, BACnet ReadProperty, Omron FINS identity, Beckhoff ADS/AMS ServerInfo and bounded
ReadDeviceInfo/ReadState requests, Niagara Fox hello, DNP3 Group 0 device attributes, NetBIOS Node
Status, SMB1/2/3 and RPC NTLM challenge identity, OPC UA asset discovery,
HTTP/HTTPS status/title/Server-header collection,
SNMP GET/WALK, and LLDP. It exports
`otserver-scan` schema-version-2 JSON for OTserver.

The canonical wire contract is `contracts/otserver-scan-v2.schema.json`.
Contract changes require coordinated updates in OTserver's importer. Product overview and first-scan
instructions are in `README.md`; detailed operator and development guidance follows here.

## Safety Rules

- Require `--ack-authorized` for every scan.
- Refresh the selected interface's current source MAC at scan start in the shared CLI/GUI path;
  log stale configured MACs and export the actual sender MAC. With ARP enabled, native protocols,
  SNMP, and LLDP use discovered, unambiguous MAC/IP pairs. Only explicit ARP disablement enables
  IP probing independently of Layer-2 discovery; never substitute a gateway MAC for a routed target.
- `--allow-dcp-source`, `allowDcpSource`, and the GUI toggle run DCP before ARP, add reported DCP IPs
  to the ARP sweep, and allow unambiguous DCP identities outside the configured range into later IP
  probes; preserve MAC correlation and OUI vendor resolution.
- Keep discovery read-only. Do not add configuration writes, DCP Set, SNMP SET, DNP3 writes,
  operates, class assignment, freezes, or restarts, brute force, exploits, vulnerability scripts, or
  Modbus requests without an explicit product decision and safety review.
- Keep protocol framing and parsing in `src/protocols/` or the existing dedicated modules. Reject
  truncated, oversized, mismatched, or unsolicited responses.
- Beckhoff ADS sends one unicast ServerInfo request to UDP 48899 and only `ReadDeviceInfo` and
  `ReadState` ADS commands over TCP 48898 to selected AMS ports. Validate the ServerInfo cookie,
  service, tags and response size, and each AMS response's reversed NetIDs/ports, command, flags,
  invoke ID, and declared lengths. Never send ADS commands other than `ReadDeviceInfo` and
  `ReadState`; no writes, symbol/process-image reads, notifications, or system-service operations.
  Never create routes or infer a target NetID from its
  IPv4 address. An explicitly configured target NetID is an operator assertion; otherwise skip ADS
  TCP reads if UDP discovery fails. Targets may require a pre-existing authorized AMS route. Keep
  ADS runtime identity/state separate from hardware model, serial, firmware, and online status.
  Do not negotiate Secure ADS, downgrade security, or try alternate secure ports. `--no-ads`,
  `noAds`, the GUI toggle and legacy `noProtocols` disable this probe.
- PNIO record replies may use the advertised endpoint port or EPM port 34964 as their UDP source.
  In either case, require the target MAC/IP, client UDP port, and matching RPC object, interface,
  activity, sequence, and operation before accepting or acknowledging fragments.
- With PROFINET enabled, run PNIO after merging ARP and DCP discovery. Probe every unambiguous
  discovered MAC/IPv4 pair in the shared IP probe scope; `allowDcpSource` permits discovered
  out-of-range targets. Never invent a MAC for an undiscovered IP. Use the shared two-second RPC
  timeout on Windows and Linux. Report missing interface/device IPv4, unavailable Npcap, ambiguous
  addresses, and per-record failures in exported warnings. Failed records must retain successful
  reads; failed API/module enumeration must still permit primary I&M0 at API 0, slot 0, subslot 1
  and its advertised optional records. Cancellation stops further requests and retains partial data.
- Active DCP must verify that its source MAC belongs to the selected physical interface. Send
  Identify-All once with `ResponseDelayFactor` `0x0080`; never use zero or rapid retries.
  After a successful send, collect replies for at least 60 seconds unless cancelled or capture
  fails. Quiet reads do not end collection; filter and deduplicate confirmed Identify responses
  as they arrive.
- NetBIOS uses one unicast wildcard NBSTAT query to UDP 137. Keep the reported UNIT_ID as raw
  evidence, never as an override for ARP/DCP identity or a way to resolve MAC-less targets.
  It is enabled by default; `--no-netbios`, `noNetbios`, and the GUI toggle disable it.
- HTTP/HTTPS discovery sends one paced `GET /` to TCP 80 and 443 respectively, without proxies,
  redirects, authentication, cookies, or retries. HTTPS discovery always disables certificate and
  hostname validation. Bound each request to two seconds and body collection to 64 KiB; retain
  status and Server-header evidence on body failure. Export listener-scoped `raw.protocol`,
  `raw.statusCode`, `raw.title`, and `raw.server` under the existing `unknown` source. Never promote
  a title or server banner to device identity, OS, or firmware. `--no-http`, `noHttp`, the GUI toggle,
  and legacy `noProtocols` disable both listeners. Upload/controller TLS settings remain independent.
- SMB uses TCP 445, SMB2/3 negotiation and only the first NTLM SESSION_SETUP; RPC uses TCP 135
  and one EPM bind carrying NTLM Type 1. Never send NTLM Type 3/AUTH3, authenticate, enumerate
  shares/endpoints, activate DCOM, or execute WMI/WinRM commands in these probes. Both are enabled
  by default, with `--no-smb`/`noSmb`, `--no-rpc`/`noRpc`, GUI toggles and legacy `noProtocols`
  disablement. Export them as existing `os-fingerprint` observations with `raw.protocol` `smb` or
  `rpc`, retaining reported NT versions and candidate releases. A dialect is not an OS version;
  NTLM versions may be synthesized by compatible implementations. Do not infer edition, client
  versus server on shared builds, UBR, installed hotfixes, or patch compliance from a challenge.
- SMB may reconnect once with SMB1 `NT LM 0.12` after a correlated SMB2 `STATUS_NOT_SUPPORTED`
  or a connection close/reset before any negotiation response bytes. Never fall back on malformed,
  partial, mismatched, or timed-out responses, or after an accepted SMB2 negotiation. SMB1 uses
  negotiation and at most one extended-security Type 1 SESSION_SETUP_ANDX, without AndX chaining.
  Classic-security servers retain negotiation/domain evidence only: never send a classic/anonymous
  login or an LM/NT challenge response. Preserve native OS/LAN-manager strings separately from
  NTLM versions, and unknown OEM bytes without lossy decoding. Existing SMB toggles disable all
  dialects; SMB1 remains `os-fingerprint` with `raw.protocol` `smb` and `raw.smbVersion` 1.
- Preserve process-wide `src/traffic.rs` pacing: 35 explicit ARP requests/s and approximately 350
  aggregate discovery operations/s, 70% of the supplied site ceilings (50 and 500). Serialize raw
  ARP sends and Windows `SendARP` calls through the blocking send gate, including syscall retries;
  never accumulate catch-up bursts. IP-target starts consume the aggregate budget, not the strict
  ARP budget, since TCP/UDP throughput need only stay roughly within limits. Receive during
  paced sweeps and honor cancellation. These are application limits, not an on-wire guarantee for
  OS-generated ARP/TCP or protocol-library traffic; do not label them universally safe.
- Credentials belong in executable-adjacent `otter.json`. Load legacy `otscanner.json` only when
  `otter.json` is absent. These local CLI/GUI flows must continue to work independently of managed
  `controller` mode. Never write credentials to logs or scan exports.
- Controller v1 uses outbound HTTPS only (HTTP loopback for development), sensitive machine headers,
  and no redirects. Bare loopback addresses normalize to HTTP; other hosts require explicit HTTPS.
  Require local `--ack-authorized`; apply snapshots through the shared scan path.
  Keep machine credentials in Secret Service/Windows Credential Manager where available, with an
  atomic permission-restricted file fallback. Unattended installations explicitly use that file store
  to operate without an interactive login. Report the computer name and at most 32 available
  adapters (technical/friendly names, description, MAC, and up to 16 IPv4/IPv6 addresses) at
  enrollment and during polling; never include credentials in this report or persist protocol
  credential snapshots.
- Persist managed assignment state before starting probes; uncertain interrupted discovery must not
  be replayed. Resume saved uploads/finish by run/import ID. Keep lease heartbeats during scans and
  uploads; cancellation, lease loss, terminal responses, or rejected authentication must prevent stale
  uploads. Credential rotation must be durable before switching the in-memory credential.
- A controller URL mismatch may be overridden only with explicit `--enroll --overwrite-state-dir`.
  Replace saved enrollment and run state only after successful enrollment; retain scan exports and
  do not send previous-controller credentials, assignments, or import IDs to the new controller.
- Persist credential-safe run failure reasons before sending the finish request, and retain them
  across retries/restarts. Use fixed setup messages and allowlisted discovery failure categories;
  never forward arbitrary protocol error text or managed credential snapshots into run messages.
- Direct imports use OTserver's `asset-imports` REST API so authorization, validation, merging, and
  auditing remain application-owned. Bound uploads to a 10-second connection timeout, five-minute
  total deadline, and 16 MiB response body; retain the local scan on failure.
- SNMP and PNIO component references are observation-local under `raw.physicalEntities`, with
  `raw.observationId`, explicit subjects, containment, and component-scoped serial claims. Preserve
  original ENTITY-MIB/PNIO data. Only a unique root ENTITY-MIB chassis/stack may supply device
  identity; module-only or ambiguous inventories must not. PNIO's legacy device-level manufacturer
  and software fields come only from API 0, slot 0, subslot 1; component serials stay scoped.
- Export the selected scan interface's current IP addresses separately from its source MAC.
- Keep application/runtime versions separate from firmware. BACnet exports `applicationSoftwareVersion`;
  Fox exports `applicationName`, `applicationSoftwareVersion`, `runtimeName`, and `runtimeVersion`,
  retaining successful listener evidence when another listener fails.
- OPC UA normalized identity comes from one asset entry; all entries retain scoped fields and serials
  under `raw.assets`, with `raw.normalizedAssetRef` identifying the selected entry. IEC 61850 never
  fills normalized fields from another logical device; preserve node-scoped evidence and serials in
  `raw.nodeObservations`, with `raw.normalizedLogicalDevice` and `raw.fieldSources`. These references
  are observation-local, not identities for merging assets or substitutes for MAC correlation.

## Platform Rules

- Linux raw Ethernet uses `AF_PACKET` and requires root or `CAP_NET_RAW`.
- Windows ARP prefers Npcap on the selected adapter: send one paced request per target, drain replies
  between sends, and apply one response grace period after the final send. Reuse Linux ARP framing
  and reply validation; accept only requested targets. Keep sends under the shared blocking gate.
  Without an available Npcap binding, use serial Win32 `SendARP`; each call waits for resolution or
  an OS timeout, so sparse ranges are slow. Log the selected path. Never retry a failed raw sweep
  through `SendARP`, or parallelize blocking `SendARP` calls to bypass pacing.
  Active DCP dynamically loads installed Npcap `Packet.dll` from
  its native System32 subdirectory and binds the selected physical adapter by GUID. Driver
  installation must remain explicit and must never be a scan side effect.
- If Npcap is unavailable, passive Windows discovery uses Microsoft pktmon.
- Preserve the current OPC UA limits: SecurityPolicy None, no continuation points, batches of at
  most 64 reads, no certificate authentication, and default ports 4840, 4841, and 48400.

### Platform operation and release builds

- The selected interface controls Layer-2 capture, ARP, and DCP. IP probes use the operating system's
  route table, not an interface binding. Multi-homed hosts need suitable OS routes. Export this as
  `scan.interface.ipRoutePolicy: "operating-system"`. Windows pktmon captures all NICs; retain passive
  PROFINET frames only when their destination MAC matches the selected adapter.
- Npcap is installed separately, never during a scan. Its free license permits up to five
  installations but not redistribution; larger or bundled deployments need appropriate OEM licensing.
  Otter does not use or modify a TAP adapter or Windows Network Bridge.
- Raspberry Pi releases use `otserver-otter-linux-aarch64.tar.gz` for Pi 3, 4, 5, and Zero 2 W with
  64-bit Raspberry Pi OS Bookworm or newer and `libssl3`. They are headless. Build natively with
  `cargo build --locked --release --no-default-features`.
- Build Windows with `cargo build --release --target x86_64-pc-windows-msvc`. The GUI detaches its
  console window; CLI commands retain normal terminal input/output.
- Release versions come from the triggering Git tag; local builds use the nearest reachable tag,
  falling back to the Cargo package version without Git metadata. `OTTER_BUILD_VERSION` overrides
  this for external builds. Keep CLI, GUI, scan exports, and Windows Explorer versions consistent.
- Tagged releases publish signed SLSA provenance for the SHA-256 digest of each Linux archive and
  Windows executable. This is separate from Windows Authenticode signing, which requires a trusted
  code-signing certificate or managed signing service.

## Local configuration and direct uploads

Place `otter.json` beside the executable. A single object remains supported:

```json
{
  "targets": ["192.168.1.0/24"],
  "interface": "eth0",
  "sourceMac": "00:11:22:33:44:55",
  "output": "scan.otserver.json",
  "snmp": { "version": "2c", "community": "public" }
}
```

The root may instead be an array. Each entry needs a unique, non-empty `name` and a distinct resolved
output path. CLI values override every entry; `OTSERVER_API_KEY` overrides each entry's `apiKey`.
A shared `--output` cannot be used when it makes multiple outputs collide. Relative paths resolve
from the current working directory. Never read `--ack-authorized` from configuration.

The GUI clones selected settings when adding a configuration, assigns a unique name/output, and
converts single-object files to arrays as needed. It offers **Run Selected** and **Run All**. CLI
array runs proceed sequentially and continue after configuration, scan, or upload failures.
**Stop Scan** writes partial output when possible and skips pending configurations. Exit code `0`
means all scans completed, `2` means valid output contains partial failures, and `1` means a
configuration, scan, or upload failed; failures take precedence in multi-configuration runs.
GUI scans are local-export only: strip legacy `serverUrl`/`site`/`apiKey` from transient scan inputs
and never read `OTSERVER_API_KEY` there. Preserve those fields for CLI/config-file direct uploads.
The GUI's controller section enrolls with a masked single-use token and offers **Install controller**
after enrollment. Run enrollment/installation off the UI thread, require the authorization checkbox,
and never persist the token or managed protocol credentials.

All discovery protocols are enabled by default. CLI `--no-<protocol>` switches and JSON `noArp`,
`noProfinet`, `noS7`, `noEnip`, `noBacnet`, `noFins`, `noFox`, `noDnp3`, `noIec61850`, `noNetbios`,
`noSmb`, `noRpc`, `noHttp`, `noAds`, `noOpcua`, `noSnmp`, and `noLldp` disable them individually.
SNMP inventory and LLDP topology share credentials but have independent switches. The GUI exposes
matching toggles.

ADS discovery uses `adsTargetNetIds` to map target IPv4 strings to their six-octet AMS NetIDs when
UDP ServerInfo is unavailable, `adsSourceNetId` to override the scanner NetID derived from the local
connection address, and `adsPorts` to select up to eight logical AMS endpoints. Empty or omitted
`adsPorts` queries the system service and the first TwinCAT 3/TwinCAT 2 PLC runtimes. AMS ports are
not TCP ports. CLI options `--ads-target-netid IP=NETID`, `--ads-source-net-id NETID`, and repeated
`--ads-port PORT` override their respective config values.

### SNMP and OPC UA credentials

`snmp` accepts one credential object or a list tried in order per target, skipping duplicates.
Without settings, use SNMPv2c community `public`. Explicit versions `1`, `2c`, and `3` never fall
back. Version `auto` tries v3 when a username exists, then v2c, then v1, stopping on success.
SNMPv3 supports an optional `contextName` (empty by default):

```json
{
  "snmp": [
    {
      "version": "3",
      "username": "inventory",
      "contextName": "optional-snmp-context",
      "authProtocol": "sha256",
      "authPassword": "...",
      "privacyProtocol": "aes128",
      "privacyPassword": "..."
    },
    { "version": "2c", "community": "public" }
  ]
}
```

`opcuaPorts` defaults to `[4840, 4841, 48400]`. `opcuaCredentials` accepts one
`{ "username": "inventory", "password": "..." }` object or a list tried in order after anonymous
access fails. Legacy `opcuaUsername`/`opcuaPassword` remains supported. SecurityPolicy None sends
passwords unencrypted; never describe this path as encrypted authentication.

Both credential lists are editable in GUI tables with add/remove actions and masked passwords.
Local credentials remain plaintext in `otter.json`; restrict access (for example,
`chmod 600 otter.json`). Logs may show sanitized SNMP version/security choices, never secrets.
The GUI log is timestamped, selectable, auto-scrolling, and clearable; preserve scan/save status and
the native output-file picker.

### Direct OTserver import

Set `serverUrl`, `site`, and `apiKey` in configuration, or use CLI flags with an environment key:

```bash
OTSERVER_API_KEY='...' otserver-otter scan \
  --target 192.168.1.0/24 \
  --interface eth0 \
  --source-mac 00:11:22:33:44:55 \
  --server-url https://otserver.example \
  --site PAYLOAD_SITE_ID \
  --ack-authorized
```

Prefer `OTSERVER_API_KEY` over a stored API key for automation. The site is a Payload document ID;
the user needs read/write access there. Write and validate the local JSON before posting it, and
retain it on upload failure. `otserver-otter validate scan.otserver.json` validates an export.

For direct uploads and controller connections, `--http-proxy URL` / `--https-proxy URL` select
explicit proxies per destination scheme; the other scheme connects directly. Direct-upload flags
must be supplied again on later starts; controller connection options are saved in private state.
`--ignore-self-signed` disables all TLS certificate and hostname validation, not just self-signed
certificate rejection. In controller mode that choice is saved for subsequent starts too.

## Managed controller operation

Enroll with `otserver-otter controller --server-url https://otserver.example --enroll --ack-authorized`
and supply the single-use token on stdin. Restart without `--enroll` to reuse credentials. Match
OTserver's `OTSERVER_PUBLIC_URL`; bare `127.0.0.1:3000`, `localhost:3000`, and `[::1]:3000` normalize
to HTTP. Other hosts require explicit HTTPS. No scanner-side listener is opened.

- `controller --enroll-only --enroll --server-url URL --ack-authorized` saves enrollment without
  polling; the GUI uses the same initialization path. Omit `--server-url` after enrollment to reuse
  the saved URL. Poll interval, queued-import mode, credential storage, proxies and TLS override
  survive restarts in private state. Fresh GUI enrollment can replace connection settings.
- `controller --install --ack-authorized` installs and starts only the managed controller, then
  exits; combine `--enroll --install --server-url URL` for first-time setup. Run under the intended
  normal OS user. Stop an existing controller before re-enrolling/updating; never kill an active scan
  to install over it. Retain enrollment and exports on install failure and allow retry.
- Linux installation copies to `~/.local/bin/otserver-otter`, writes the systemd user unit
  `otserver-otter-controller.service`, enables lingering for boot/after-logout operation, and verifies
  `cap_net_raw=ep` on the installed executable. Escalate only the required `setcap`/`loginctl` commands
  through terminal sudo or desktop PolicyKit. Do not run the controller or entire installer as root,
  grant `CAP_NET_ADMIN`, or set `NoNewPrivileges` on a unit relying on executable capabilities.
- Windows installation uses `%LOCALAPPDATA%\Programs\OTserver Otter` and a SID-named Task Scheduler
  task with a login trigger, S4U/non-interactive current-user principal, IgnoreNew instance policy,
  unlimited execution time and battery operation. Start it immediately if idle. S4U permits operation
  after logout without storing a Windows password but needs batch-logon rights; report denied task
  registration with actionable guidance. It cannot use Windows-integrated network credentials/EFS.
  Npcap stays separately installed and must permit capture for the task's user.
- Both installers move only the enrollment-issued machine credential into the existing private-file
  store and pin rotation to file storage, allowing startup without a desktop keyring. Never save
  server-supplied SNMP/OPC UA snapshots. Keep tokens, machine secrets and proxy values out of service
  commands/task definitions. Escape systemd specifiers/environment syntax and Windows argument paths.

- Default state lives at `$XDG_STATE_HOME/otserver-otter` or `~/.local/state/otserver-otter` on Linux,
  and `%LOCALAPPDATA%\otserver-otter` on Windows. `--state-dir PATH` overrides it. One process owns
  the directory; use the same OS account and directory across restarts.
- `--file-credentials` explicitly selects the private file fallback instead of the OS credential
  store. Unix directories/files must belong to the current user with modes 0700/0600; Windows ACLs
  restrict state to the current user. Protocol credential snapshots remain memory-only.
- `--enroll --overwrite-state-dir` permits controller takeover with a fresh token. Preserve old
  state on failed enrollment and retain scan exports. Omit both flags on subsequent starts.
- `--poll-seconds 30` sets the minimum interval (1–300 seconds); the server may request longer idle
  intervals. Once enrolled, polling network/429/5xx failures and unavailable adapter inventory keep the
  controller running and retry every five minutes until recovery. Successful polling restores the
  normal interval; authentication rejection still requires re-enrollment.
- Set a capture interface explicitly on multi-adapter hosts. An omitted source MAC comes from the
  selected adapter. Managed scans use the shared validation, read-only probes, and traffic pacing.
- Heartbeats report bounded progress every 15 seconds and renew a 30-minute lease. Cap accepted
  leases at 30 minutes and stop five seconds before expiry; preserve shorter server deadlines.
  Cancellation, lease loss, terminal responses, or authentication rejection stop work and prevent
  stale uploads.
  Managed output omits probe details and controller bodies/credentials.
- Interrupted discovery becomes failed work, never an automatic rescan. Completed exports resume
  byte-identical upload retries; known import IDs resume finishing. Retain `RUN_ID.otserver.json`
  in the state directory, including on failure; operators manage export retention.
- Managed upload network failures and retryable HTTP responses wait two minutes between attempts,
  with at most five retries after the initial attempt. Persist each attempt before sending so
  restarts preserve the limit; a resumed retry waits two minutes. Keep heartbeats active during
  waits and uploads. Exhaustion records a failed run with a retained local export and retries only
  its finish request. Accepted imports that fail processing are not upload transport failures.
- `--queued-imports` requires queued imports enabled in the manager's Application settings and
  healthy manager workers. Scanner completion is distinct from import completion. Idle polling checks
  pending/running imports by ID;
  failed queued imports receive at most one explicit retry by ID without re-uploading terminal work.
- Rotate credentials when less than 30 days remain, durably saving the secret/reference first.
  Authentication failure or a lost enrollment/rotation response requires re-enrollment because the
  server consumes or revokes the prior token immediately.

## Protocol evidence reference

- SNMP covers MIB-II identity, LLDP and DOT1/DOT3/PNO extensions, MRP monitoring, IF-MIB/IP-MIB,
  ENTITY-MIB components, BRIDGE/Q-BRIDGE ports/VLANs, and Siemens AUTOMATION-SYSTEM-MIB identity.
  With ARP disabled, only valid interface, bridge, or LLDP chassis MAC evidence may identify an asset;
  forwarding-table MACs remain port evidence. Preserve component-to-interface mappings where present.
- DCP exports numeric `vendorId`/`deviceId` alongside full parsed blocks, plus `fields.vendor`
  resolved from the bundled manufacturer table (42 → `SIEMENS AG`). Unknown IDs omit `vendor`.
  EtherNet/IP preserves every valid List Identity transport response; S7 preserves accepted TSAP
  access and both identity SZLs.
  PNIO component references use `pnio:<api>:<slot>[:<subslot>]` and retain original records,
  containment, identification numbers, I&M revisions, and scoped serial claims.
- DNP3 uses TCP 20000: link reset followed by Group 0 Variation 254 device-attribute Read with the
  all-objects qualifier, pipelined for four common outstation/master pairs. Keep hardware revisions
  separate from firmware. Do not probe DNP3/UDP, TLS-wrapped DNP3, or Secure Authentication.
- IEC 61850 uses MMS/TCP 102 for advertised identity, health, breaker-position, blocking, and
  operation-count attributes. Do not access control, report, setting-group, file, or write services.
- OPC UA preserves hardware revisions and patch identifiers as inventory evidence, not compliance
  verdicts. Fox retains listener responses in `raw.transportResponses` even on partial failure.
- EtherNet/IP uses correlated ListIdentity sender contexts. After a valid TCP identity, it opens
  one bounded explicit-message session for Identity Object GetAttributesAll (class 1, instance 1),
  TCP/IP Interface configuration and hostname GetAttributeSingle (class 0xF5, instance 1, attributes
  5 and 6). These are the only additional CIP services; never add ForwardOpen, writes, routing,
  or rack enumeration here. Retain disagreements as evidence, not identity overrides.
- LLDP combines SNMP-reported neighbors with a concurrent 30-second passive selected-link capture
  (Linux AF_PACKET or Windows Npcap). The passive path sends no frames, observes at most 512
  neighbors, expires TTLs and honors withdrawal/cancellation. Management addresses never expand IP
  probe scope. Preserve chassis/port subtypes and LLDP-MED inventory; remote inventory must not
  become the reporting SNMP agent's identity. Missing Npcap does not disable SNMP LLDP collection.
- SNMP software revisions and OPC UA SoftwareRevision remain `softwareRevision`, never a fallback
  for firmware. OPC UA endpoint security/certificate evidence and standard server BuildInfo remain
  application-scoped under `raw`, separate from represented assets. Certificate retention is bounded
  to 16 KiB per endpoint and endpoint retention to 64 entries. Advertised URLs are never followed.
- Preserve successful S7 SZLs, BACnet properties, FINS transports and partial SNMP walk rows after
  later failures. Export collection outcomes and field sources with protocol evidence. Incomplete
  ENTITY-MIB parent/class walks cannot establish unique root identity. DNP3 attributes retain set,
  variation, datatype and bytes; only explicit standard-set attributes supply normalized identity.
  Datatype 254 is an attribute list, not a vendor string convention.
- NetBIOS retains name tables, suffixes, flags, workgroup, unit ID, and raw replies. Prefer workstation
  over server names. No broadcast, registration, credentials, or SMB session is needed. OTserver must
  recognize the `netbios` source in schema version 2.
- SMB negotiation/identity phases and RPC exchanges each have two-second deadlines. SMB1 uses direct
  TCP 445, not NetBIOS TCP 139, and installs no OS SMB1 component. Preserve `raw.dialect`,
  `raw.serverStrings`, original NTLM challenges, `reportedVersion`, and `windowsCandidates`.
  Build 17763 may mean Windows 10 1809 or Server 2019; build 26100 may mean Windows 11 24H2 or
  Server 2025. Unknown builds retain numeric versions without guessed releases. Compatible servers
  can synthesize NTLM versions; exact installed OS/patch inventory needs a separately authorized
  authenticated path.

## Virtual OT lab

`./lab/test.sh` exercises Linux discovery against deterministic virtual devices. It requires Linux
containers, Docker Engine with Compose, and daemon access; Windows developers may use WSL2.
Scanner/Siemens containers receive only `NET_RAW`; no host networking or published protocol ports.
The Siemens DCP responder waits 55 seconds to verify the one-minute capture window. JSON and logs
remain under `lab/artifacts/`.
`./lab/test-pnio.sh` also tests ARP-only discovery with silent DCP and rejected API/module
enumeration, confirming primary firmware recovery and per-record diagnostics.

Run `./lab/test-windows.ps1` from Windows PowerShell for the native executable smoke test. It binds
responders only to Docker/WSL's host-only Hyper-V adapter. All forwarded replies share that adapter's
MAC, so this checks protocol clients, not distinct device identity. The importable scan is deleted
after validation; retain only the text summary and Compose log. DCP is disabled because Docker
Desktop does not bridge raw Ethernet to Windows capture drivers. Validate active Windows DCP and
multi-device MAC discovery on physical Layer-2 devices or a dedicated external test interface after
Npcap changes. SMB/RPC are excluded because host services own TCP 445/135.

Responders use pinned Snap7, libIEC61850, SNMP Simulator, checksum-pinned OpENer/BACnet Stack,
asyncua, and bounded FINS/Fox/DNP3 implementations. NetBIOS uses Samba `nmbd`; SMB/RPC use real
`smbd`/`samba-dcerpcd` without completed authentication. An isolated SMB1-only Samba service checks
fallback, names, native strings, disablement, and MAC-less unresolved output. Classic security and
old short NTLM challenges use Rust fixtures, not live legacy-Windows interoperability tests.
Validate actual Windows releases separately with their firewall and NTLM policies.

The lab checks three allowlisted CIP reads against OpENer, typed DNP3/configuration evidence,
SNMP ENTITY-MIB UUID/URI and remote LLDP-MED scoping, OPC UA application/device version separation,
and retention of UDP FINS identity after a malformed TCP response. The Fox lab device also serves
HTTP/HTTPS, checking status/title/Server-header evidence, invalid certificate acceptance,
disablement, and MAC-less endpoint scoping. Passive LLDP frames are injected in the scanner's
isolated network namespace because Linux bridges suppress reserved LLDP multicast;
this exercises AF_PACKET reception/decoding, not physical switch forwarding or Windows capture.
The scanner lab Docker build uses BuildKit registry/target caches for repeatable incremental builds.

### Remote-management gate setup

From the management checkout containing `otserver-otter/`:

```bash
pnpm install --frozen-lockfile
./otserver-otter/lab/test-controller.sh
```

Requires Linux, Rust, Node.js 22, pnpm 10, Python 3, OpenSSL with development headers, and Docker or
Podman. Set `CONTAINER_RUNTIME=podman` to choose explicitly. The gate builds the headless client,
tests controller behavior and HTTPS recovery, and runs the full management integration suite.
It owns its replica set/upload directory and ignores caller and `.env` database settings.
Coverage includes enrollment/inventory, configurations/secrets, run lifecycle, scheduling, sync/queued
imports, authorization, auditing, rotation, revocation, and UI component controls. Managed tests
disable discovery probes; protocol interoperability remains the separate lab's responsibility.
Any failed stage fails the gate; preserve stage logs, MongoDB logs, and management JUnit reports.

## Generated Files

- Commit `Cargo.lock` when `Cargo.toml` changes.
- Regenerate `src/profinet_database.rs` with `python3 databases/generate_database.py` whenever
  `databases/Man_ID_Table.xml` or `databases/Profile_ID_Table.xml` changes; the compiled tables
  keep the binary standalone.
- Never commit `otter.json`, legacy `otscanner.json`, scan output, build output, Docker lab
  artifacts, packet captures, credentials, or Python/Rust caches.

## Checks

```bash
cargo fmt -- --check
python3 -B databases/test_generate_database.py
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo llvm-cov --lib --fail-under-lines 90 --summary-only -- --test-threads=1
./lab/test.sh
./lab/test-pnio.sh
python3 lab/controller_verify.py target/debug/otserver-otter
./lab/test-controller.sh
git diff --check
```

Scanner branch, loop, and parser logic needs a focused Rust unit test. Protocol interoperability
belongs in the Docker lab. The controller HTTPS lab is also runnable standalone after a headless
build. Management's `pnpm test:otter-client` builds the headless executable and exercises enrollment,
import, and saved-credential restart against Payload REST and the integration-test replica set.
Its `tests/int/otter-client.int.spec.ts` also accepts an existing build via `OTTER_CLIENT_BIN`.
`./lab/test-controller.sh` is the full remote-management CI gate. Run from an Otter checkout at
`MANAGEMENT/otserver-otter` with management dependencies installed; it builds/tests the controller,
runs the HTTPS lab, and runs the entire management integration suite with the real client enabled.
It owns a disposable Docker/Podman MongoDB replica set and must never reuse operator database URLs.
Reports live under `lab/artifacts/controller.*/` and record both source revisions plus the client
binary digest. Remote-management CI, including Otter release/tag runs, defaults to OTserver `main`;
`management_ref` or the `OTTER_MANAGEMENT_REF` repository variable overrides it. Release/tag runs
require this exact-pair gate.

On Windows, the Fox TLS retry test requires a process context that can acquire Schannel outbound
credentials. A restricted sandbox may return `SEC_E_NO_CREDENTIALS` before sending ClientHello;
verify that failure in a normal user context rather than weakening or skipping the test.

The HTTPS loopback test uses the public, test-only PKCS#12 identity in `src/protocols/fixtures/`;
regeneration instructions are alongside it. Windows GNU test binaries can also run under Wine on
Linux, but Wine 11 does not preserve protected file DACLs. Validate the controller ACL test on
native Windows; do not relax its security assertions to make Wine pass.
