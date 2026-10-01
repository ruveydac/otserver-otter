#!/usr/bin/env python3
"""Siemens lab device: Snap7, PROFINET DCP/PNIO, and SNMP Simulator."""

import os
import signal
from uuid import UUID
import subprocess
import threading
import time

from scapy.all import Ether, IP, Raw, UDP, get_if_hwaddr, sendp, sniff
from snap7.server import Server

INTERFACE = "eth0"
DCP_MULTICAST = bytes.fromhex("010ECF000000")
ETHERTYPE = bytes.fromhex("8892")
EPM_PORT = 34964
PNIO_PORT = 49155
NIL_UUID = "00000000-0000-0000-0000-000000000000"
EPM_INTERFACE_UUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
PNIO_INTERFACE_UUID = "dea00001-6c97-11d1-8271-00a02442df7d"
PNIO_OBJECT_UUID = "dea00000-6c97-11d1-8271-0001002a0007"
RESPONSE_DELAY_SECONDS = float(os.environ.get("OTTER_DCP_RESPONSE_DELAY_SECONDS", "0"))


def block(option: int, suboption: int, payload: bytes) -> bytes:
    value = b"\0\0" + payload
    result = bytes((option, suboption)) + len(value).to_bytes(2, "big") + value
    return result + (b"\0" if len(value) % 2 else b"")


def dcp_blocks(mac: bytes) -> bytes:
    uuid = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    return b"".join(
        [
            block(1, 1, mac),
            block(
                1,
                3,
                bytes((172, 30, 0, 10, 255, 255, 255, 0, 172, 30, 0, 1))
                + bytes((1, 1, 1, 1, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0)),
            ),
            block(2, 1, b"ET 200SP Lab"),
            block(2, 2, b"siemens-plc-1"),
            block(2, 3, bytes.fromhex("002A1234")),
            block(2, 4, bytes((1, 0))),
            block(2, 5, bytes((1, 3, 2, 1, 2, 2))),
            block(2, 6, b"port-001.siemens-plc-1"),
            block(2, 7, bytes.fromhex("0102")),
            block(2, 8, bytes.fromhex("002A5678")),
            block(2, 10, bytes.fromhex("003F")),
            block(2, 11, bytes.fromhex("001F")),
            block(3, 61, bytes.fromhex("3D0101")),
            block(3, 255, bytes.fromhex("FF0100")),
            block(6, 1, bytes.fromhex("0001")),
            block(7, 1, uuid + b"ot-lab-domain"),
            block(7, 2, bytes.fromhex("0001")),
            block(7, 3, uuid),
            block(7, 4, uuid),
            block(7, 5, bytes.fromhex("002A12340102")),
        ]
    )


def respond_dcp(packet: Ether) -> None:
    request = bytes(packet)
    if (
        len(request) < 30
        or request[:6] != DCP_MULTICAST
        or request[12:14] != ETHERTYPE
        or request[14:18] != bytes.fromhex("FEFE0500")
        or request[26:30] != bytes.fromhex("FFFF0000")
    ):
        return
    response_delay_factor = int.from_bytes(request[22:24], "big")
    if not 1 <= response_delay_factor <= 0x1900:
        return
    mac = bytes.fromhex(get_if_hwaddr(INTERFACE).replace(":", ""))
    if RESPONSE_DELAY_SECONDS > 0:
        time.sleep(RESPONSE_DELAY_SECONDS)
    elif response_delay_factor > 1:
        spread = int.from_bytes(mac[-2:], "big") % response_delay_factor
        time.sleep(spread * 0.01)
    data = dcp_blocks(mac)
    response = (
        request[6:12]
        + mac
        + ETHERTYPE
        + bytes.fromhex("FEFF0501")
        + request[18:22]
        + b"\0\0"
        + len(data).to_bytes(2, "big")
        + data
    )
    if len(response) < 60:
        response += bytes(60 - len(response))
    sendp(Ether(response), iface=INTERFACE, verbose=False)


def run_dcp() -> None:
    sniff(
        iface=INTERFACE,
        store=False,
        prn=respond_dcp,
        lfilter=lambda packet: packet.haslayer(Ether) and packet.type == 0x8892,
    )


def wire_uuid(value: str) -> bytes:
    raw = UUID(value).bytes
    return raw[3::-1] + raw[5:3:-1] + raw[7:5:-1] + raw[8:]


def record_block(block_type: int, payload: bytes, version: tuple[int, int] = (1, 0)) -> bytes:
    return (
        block_type.to_bytes(2, "big")
        + (len(payload) + 2).to_bytes(2, "big")
        + bytes(version)
        + payload
    )


def module_record(block_type: int, version: tuple[int, int]) -> bytes:
    payload = (
        (1).to_bytes(2, "big")
        + (0).to_bytes(4, "big")
        + (1).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (0x1111).to_bytes(4, "big")
        + (1).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (0x2222).to_bytes(4, "big")
    )
    return record_block(block_type, payload, version)


def im5_record() -> bytes:
    payload = bytearray(b" " * 152)
    payload[0:64] = b"A" * 64
    payload[64:128] = b"B" * 64
    payload[128:130] = (0x1234).to_bytes(2, "big")
    payload[130:146] = b"C" * 16
    payload[146:148] = (3).to_bytes(2, "big")
    payload[148:152] = b"V\x01\x02\x03"
    entries = [
        record_block(0x0034, bytes(payload)),
        record_block(0x0036, b""),
        record_block(0x0037, b""),
        record_block(0x0038, b""),
    ]
    return record_block(0x0025, (4).to_bytes(2, "big") + b"".join(entries))


def pnio_record(index: int) -> bytes:
    if index == 0xF821:
        return record_block(0x001A, (1).to_bytes(2, "big") + (0).to_bytes(4, "big"))
    if index == 0xF840:
        return module_record(0x0030, (1, 0))
    if index == 0xF000:
        return module_record(0x0013, (1, 1))
    if index == 0xAFF0:
        payload = bytearray(54)
        payload[0:2] = (0x1234).to_bytes(2, "big")
        payload[2:7] = b"ORD-1"
        payload[22:28] = b"SERIAL"
        payload[38:40] = (3).to_bytes(2, "big")
        payload[40:44] = b"V\x01\x02\x03"
        payload[44:46] = (4).to_bytes(2, "big")
        payload[46:48] = (0x0102).to_bytes(2, "big")
        payload[48:50] = (7).to_bytes(2, "big")
        payload[50:52] = b"\x01\x02"
        payload[52:54] = (0x003E).to_bytes(2, "big")
        return record_block(0x0020, bytes(payload))
    if index == 0xAFF1:
        return record_block(0x0021, b"FUNCTION" + b" " * 46)
    if index == 0xAFF2:
        return record_block(0x0022, b"2026-10-01" + b" " * 6)
    if index == 0xAFF3:
        return record_block(0x0023, b"DESCRIPTOR" + b" " * 44)
    if index == 0xAFF4:
        payload = bytearray(54)
        payload[0:4] = b"crc1"
        for index, value in enumerate(range(1, 11)):
            offset = 4 + index * 4
            payload[offset : offset + 4] = value.to_bytes(4, "big")
        return record_block(0x0024, bytes(payload))
    if index == 0xAFF5:
        return im5_record()
    raise ValueError(f"unsupported PNIO record 0x{index:04X}")


def pnio_header(request: bytes, body_length: int, flags: int, fragment_number: int) -> bytes:
    return (
        bytes((4, 2, flags, 0, 0x10, 0, 0, 0))
        + request[8:24]
        + request[24:40]
        + request[40:56]
        + request[56:68]
        + request[68:74]
        + body_length.to_bytes(2, "little")
        + fragment_number.to_bytes(2, "little")
        + b"\0\0"
    )


def epm_floor_uuid(value: str) -> bytes:
    return (
        (19).to_bytes(2, "little")
        + b"\x0D"
        + wire_uuid(value)
        + (1).to_bytes(2, "little")
        + (2).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
    )


def epm_body() -> bytes:
    floors = (
        epm_floor_uuid(PNIO_INTERFACE_UUID)
        + epm_floor_uuid("8a885d04-1ceb-11c9-9fe8-08002b104860")
        + (1).to_bytes(2, "little")
        + b"\x0A"
        + (2).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + b"\x08"
        + (2).to_bytes(2, "little")
        + PNIO_PORT.to_bytes(2, "big")
        + (1).to_bytes(2, "little")
        + b"\x09"
        + (4).to_bytes(2, "little")
        + bytes((172, 30, 0, 10))
    )
    tower = (
        (1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (len(floors) + 2).to_bytes(4, "little")
        + (len(floors) + 2).to_bytes(4, "little")
        + (5).to_bytes(2, "little")
        + floors
    )
    body = (
        (0).to_bytes(4, "little")
        + wire_uuid(NIL_UUID)
        + (1).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + wire_uuid(PNIO_OBJECT_UUID)
        + tower
    )
    if len(body) % 2:
        body += b"\0"
    return body + (0).to_bytes(4, "little")


def read_body(request: bytes) -> bytes:
    api = int.from_bytes(request[124:128], "big")
    slot = int.from_bytes(request[128:130], "big")
    subslot = int.from_bytes(request[130:132], "big")
    index = int.from_bytes(request[134:136], "big")
    record = pnio_record(index)
    iod = (
        (0x8009).to_bytes(2, "big")
        + (60).to_bytes(2, "big")
        + b"\x01\0"
        + (0).to_bytes(2, "big")
        + UUID(NIL_UUID).bytes
        + api.to_bytes(4, "big")
        + slot.to_bytes(2, "big")
        + subslot.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + index.to_bytes(2, "big")
        + len(record).to_bytes(4, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + b"\0" * 20
        + record
    )
    count = 64 + len(record)
    return (
        (0).to_bytes(4, "little")
        + count.to_bytes(4, "little")
        + count.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + count.to_bytes(4, "little")
        + iod
    )


def send_rpc_response(packet: Ether, request: bytes, body: bytes) -> None:
    fragments = []
    if len(body) > 64:
        split = len(body) // 2
        fragments = [(body[:split], 0x04, 0), (body[split:], 0x06, 1)]
    else:
        fragments = [(body, 0x02, 0)]
    mac = get_if_hwaddr(INTERFACE)
    for fragment, flags, number in fragments:
        payload = pnio_header(request, len(fragment), flags, number) + fragment
        response = (
            Ether(dst=packet.src, src=mac)
            / IP(src=packet[IP].dst, dst=packet[IP].src)
            / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
            / Raw(load=payload)
        )
        sendp(response, iface=INTERFACE, verbose=False)


def respond_pnio(packet: Ether) -> None:
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    request = bytes(packet[UDP].payload)
    if len(request) < 80 or request[0] != 4 or request[1] & 0x1F != 0:
        return
    operation = int.from_bytes(request[68:70], "little")
    if packet[UDP].dport == EPM_PORT and operation == 2:
        body = epm_body()
    elif packet[UDP].dport == PNIO_PORT and operation == 5:
        body = read_body(request)
    else:
        return
    send_rpc_response(packet, request, body)


def run_pnio() -> None:
    sniff(
        iface=INTERFACE,
        store=False,
        prn=respond_pnio,
        lfilter=lambda packet: packet.haslayer(Ether)
        and packet.haslayer(IP)
        and packet.haslayer(UDP)
        and packet[UDP].dport in (EPM_PORT, PNIO_PORT),
    )


def start_snmp() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            "snmpsim-command-responder",
            "--logging-method=null",
            "--v3-engine-id=80004FB8054F544C4142",
            "--data-dir=/lab/snmp-data",
            "--cache-dir=/tmp/snmpsim",
            "--agent-udpv4-endpoint=0.0.0.0:161",
            "--v3-user=inventory",
            "--v3-auth-key=lab-auth-password",
            "--v3-auth-proto=SHA256",
            "--v3-priv-key=lab-privacy-password",
            "--v3-priv-proto=AES",
            "--process-user=nobody",
            "--process-group=nogroup",
        ]
    )


def main() -> None:
    stop = threading.Event()
    for event in (signal.SIGINT, signal.SIGTERM):
        signal.signal(event, lambda *_: stop.set())

    s7 = Server(log=False)
    s7.start(tcp_port=102)
    snmp = start_snmp()
    threading.Thread(target=run_dcp, daemon=True).start()
    threading.Thread(target=run_pnio, daemon=True).start()
    try:
        while not stop.wait(0.5):
            if snmp.poll() is not None:
                raise SystemExit(f"SNMP Simulator exited with {snmp.returncode}")
    finally:
        snmp.terminate()
        try:
            snmp.wait(timeout=5)
        except subprocess.TimeoutExpired:
            snmp.kill()
        s7.stop()
        s7.destroy()


if __name__ == "__main__":
    assert len(dcp_blocks(bytes.fromhex("020000000010"))) % 2 == 0
    main()
