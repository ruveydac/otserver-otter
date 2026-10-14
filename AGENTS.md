# Agent Guide

This file applies to the entire repository. Keep it current when a change alters a durable command,
contract, or safety boundary.

## Project Summary

OTserver Otter is a read-only Rust discovery CLI and GUI for Windows and Linux. It discovers OT
assets with native ARP, PROFINET DCP Identify and PNIO I&M record reads (EPM endpoint mapping,
bounded read requests, and DCE/RPC fragmentation/FACK handling), S7 identity, EtherNet/IP List
Identity, BACnet ReadProperty, Omron FINS identity, Niagara Fox hello, DNP3 Group 0 device
attributes, NetBIOS Node Status, SMB1/2/3 and RPC NTLM challenge identity, OPC UA asset discovery,
SNMP GET/WALK, and LLDP. It exports
`otserver-scan` schema-version-2 JSON for OTserver.

The canonical wire contract is `contracts/otserver-scan-v2.schema.json`.

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
- PNIO record replies may use the advertised endpoint port or EPM port 34964 as their UDP source.
  In either case, require the target MAC/IP, client UDP port, and matching RPC object, interface,
  activity, sequence, and operation before accepting or acknowledging fragments.
- Active DCP must verify that its source MAC belongs to the selected physical interface. Send
  Identify-All once with `ResponseDelayFactor` `0x0080`; never use zero or rapid retries.
  After a successful send, collect replies for at least 60 seconds unless cancelled or capture
  fails. Quiet reads do not end collection; filter and deduplicate confirmed Identify responses
  as they arrive.
- NetBIOS uses one unicast wildcard NBSTAT query to UDP 137. Keep the reported UNIT_ID as raw
  evidence, never as an override for ARP/DCP identity or a way to resolve MAC-less targets.
  It is enabled by default; `--no-netbios`, `noNetbios`, and the GUI toggle disable it.
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
  atomic permission-restricted file fallback. Report the computer name and at most 32 available
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
- Windows ARP uses Win32 IP Helper. Active DCP dynamically loads installed Npcap `Packet.dll` from
  its native System32 subdirectory and binds the selected physical adapter by GUID. Driver
  installation must remain explicit and must never be a scan side effect.
- If Npcap is unavailable, passive Windows discovery uses Microsoft pktmon.
- Preserve the current OPC UA limits: SecurityPolicy None, no continuation points, batches of at
  most 64 reads, no certificate authentication, and default ports 4840, 4841, and 48400.

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
binary digest. Ordinary remote-management CI defaults to OTserver `main`; `management_ref` or the
`OTTER_MANAGEMENT_REF` repository variable overrides it. Otter release/tag runs require an explicit
compatible OTserver revision and this exact-pair gate.

On Windows, the Fox TLS retry test requires a process context that can acquire Schannel outbound
credentials. A restricted sandbox may return `SEC_E_NO_CREDENTIALS` before sending ClientHello;
verify that failure in a normal user context rather than weakening or skipping the test.
