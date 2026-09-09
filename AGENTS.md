# Agent Guide

This file applies to the entire repository. Keep it current when a change alters a durable command,
contract, or safety boundary.

## Project Summary

OTserver Otter is a read-only Rust discovery CLI and GUI for Windows and Linux. It discovers OT
assets with native ARP, PROFINET DCP Identify, S7 identity, EtherNet/IP List Identity, BACnet
ReadProperty, Omron FINS identity, Niagara Fox hello, DNP3 Group 0 device attributes, OPC UA asset
discovery, SNMP GET/WALK, and LLDP. It exports `otserver-scan` schema-version-2 JSON for OTserver.

The canonical wire contract is `contracts/otserver-scan-v2.schema.json`.

## Safety Rules

- Require `--ack-authorized` for every scan.
- Keep discovery read-only. Do not add configuration writes, DCP Set, SNMP SET, DNP3 writes,
  operates, class assignment, freezes, or restarts, brute force, exploits, vulnerability scripts, or
  Modbus requests without an explicit product decision and safety review.
- Keep protocol framing and parsing in `src/protocols/` or the existing dedicated modules. Reject
  truncated, oversized, mismatched, or unsolicited responses.
- Active DCP must verify that its source MAC belongs to the selected physical interface. Send
  Identify-All once with `ResponseDelayFactor` `0x0080`; never use zero or rapid retries.
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
git diff --check
```

Scanner branch, loop, and parser logic needs a focused Rust unit test. Protocol interoperability
belongs in the Docker lab.
