# Agent Guide

This file applies to the entire repository. Keep it current when a change alters a durable command,
contract, or safety boundary.

## Project Summary

OTserver Otter is a read-only Rust discovery CLI and GUI for Windows and Linux. It discovers OT
assets with native ARP, PROFINET DCP Identify and PNIO I&M record reads (EPM endpoint mapping,
bounded read requests, and DCE/RPC fragmentation/FACK handling), S7 identity, EtherNet/IP List
Identity, BACnet ReadProperty, Omron FINS identity, Niagara Fox hello, DNP3 Group 0 device
attributes, NetBIOS Node Status, OPC UA asset discovery, SNMP GET/WALK, and LLDP. It exports
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
- Active DCP must verify that its source MAC belongs to the selected physical interface. Send
  Identify-All once with `ResponseDelayFactor` `0x0080`; never use zero or rapid retries.
  After a successful send, collect replies for at least 60 seconds unless cancelled or capture
  fails. Quiet reads do not end collection; filter and deduplicate confirmed Identify responses
  as they arrive.
- NetBIOS uses one unicast wildcard NBSTAT query to UDP 137. Keep the reported UNIT_ID as raw
  evidence, never as an override for ARP/DCP identity or a way to resolve MAC-less targets.
  It is enabled by default; `--no-netbios`, `noNetbios`, and the GUI toggle disable it.
- Preserve process-wide `src/traffic.rs` pacing: 35 explicit ARP requests/s and approximately 350
  aggregate discovery operations/s, 70% of the supplied site ceilings (50 and 500). Serialize raw
  ARP sends and Windows `SendARP` calls through the blocking send gate, including syscall retries;
  never accumulate catch-up bursts. IP-target starts consume the aggregate budget, not the strict
  ARP budget, since TCP/UDP throughput need only stay roughly within limits. Receive during
  paced sweeps and honor cancellation. These are application limits, not an on-wire guarantee for
  OS-generated ARP/TCP or protocol-library traffic; do not label them universally safe.
- Credentials belong in executable-adjacent `otter.json`. Load legacy `otscanner.json` only when
  `otter.json` is absent. Never write credentials to logs or scan exports.
- Direct imports use OTserver's `asset-imports` REST API so authorization, validation, merging, and
  auditing remain application-owned.

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
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo llvm-cov --lib --fail-under-lines 90 --summary-only -- --test-threads=1
./lab/test.sh
./lab/test-pnio.sh
git diff --check
```

Scanner branch, loop, and parser logic needs a focused Rust unit test. Protocol interoperability
belongs in the Docker lab.
