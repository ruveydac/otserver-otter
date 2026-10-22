#!/usr/bin/env python3
"""Small read-only responders for protocols without maintained test emulators."""

import asyncio
import os
import ssl
import struct
import sys


def fins_payload(sid: int) -> bytes:
    response = bytearray(106)
    response[0] = 0xC0
    response[9] = sid
    response[10:12] = b"\x05\x01"
    response[14:34] = b"CJ2M-CPU32".ljust(20, b"\0")
    response[34:54] = b"02.01".ljust(20, b"\0")
    response[94:96] = (32_000).to_bytes(2, "big")
    response[96] = 64
    response[97:99] = (32_000).to_bytes(2, "big")
    response[99] = 64
    response[100] = 32
    response[101:103] = (20_000).to_bytes(2, "big")
    response[103] = 1
    response[104:106] = (4096).to_bytes(2, "big")
    return bytes(response)


def fins_tcp_frame(command: int, payload: bytes) -> bytes:
    body = command.to_bytes(4, "big") + b"\0\0\0\0" + payload
    return b"FINS" + len(body).to_bytes(4, "big") + body


ADS_TCP_PORT = 48898
ADS_UDP_PORT = 48899
ADS_COOKIE = 0x71146603
ADS_NET_ID = bytes([172, 30, 0, 21, 1, 1])


def ads_server_info_response(request: bytes) -> bytes:
    if (
        len(request) != 24
        or int.from_bytes(request[:4], "little") != ADS_COOKIE
        or int.from_bytes(request[4:8], "little") != 0
        or int.from_bytes(request[8:12], "little") != 1
        or request[12:24] != bytes(12)
    ):
        raise ValueError("invalid ADS ServerInfo request")
    return (
        struct.pack("<III", ADS_COOKIE, 0, 0x80000001)
        + ADS_NET_ID
        + struct.pack("<HI", 0, 0)
    )


class AdsUdp(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            response = ads_server_info_response(data)
        except ValueError:
            return
        self.transport.sendto(response, addr)


async def read_ams_frame(reader: asyncio.StreamReader) -> bytes:
    prefix = await reader.readexactly(6)
    if prefix[:2] != b"\0\0":
        raise ValueError("invalid AMS/TCP prefix")
    length = int.from_bytes(prefix[2:6], "little")
    if length < 32 or length > 4096:
        raise ValueError("invalid AMS frame length")
    return prefix + await reader.readexactly(length)


def ads_response(request: bytes) -> bytes:
    if len(request) < 38:
        raise ValueError("truncated AMS request")
    header = request[6:38]
    target_net_id = header[:6]
    target_port = int.from_bytes(header[6:8], "little")
    source_net_id = header[8:14]
    source_port = int.from_bytes(header[14:16], "little")
    command = int.from_bytes(header[16:18], "little")
    flags = int.from_bytes(header[18:20], "little")
    data_length = int.from_bytes(header[20:24], "little")
    invoke_id = int.from_bytes(header[28:32], "little")
    assert target_net_id == ADS_NET_ID and target_port in (10000, 851, 801)
    assert source_net_id[4:] == b"\x01\x01" and source_port == 32768
    assert flags == 4 and data_length == 0 and len(request) == 38
    if command == 1:
        name = b"OT-LAB TwinCAT3".ljust(16, b"\0")
        data = struct.pack("<I", 0) + bytes([3, 1]) + struct.pack("<H", 4021) + name
    elif command == 4:
        data = struct.pack("<IHH", 0, 5, 0)
    else:
        raise ValueError(f"unexpected ADS command {command}")
    response_header = (
        source_net_id
        + source_port.to_bytes(2, "little")
        + target_net_id
        + target_port.to_bytes(2, "little")
        + command.to_bytes(2, "little")
        + (5).to_bytes(2, "little")
        + len(data).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + invoke_id.to_bytes(4, "little")
    )
    body = response_header + data
    return b"\0\0" + len(body).to_bytes(4, "little") + body


async def handle_ads(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            request = await read_ams_frame(reader)
            writer.write(ads_response(request))
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError, AssertionError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def run_ads() -> None:
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(
        AdsUdp, local_addr=("0.0.0.0", ADS_UDP_PORT)
    )
    tcp = await asyncio.start_server(handle_ads, "0.0.0.0", ADS_TCP_PORT)
    try:
        async with tcp:
            await tcp.serve_forever()
    finally:
        udp.close()


async def read_fins_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(8)
    if header[:4] != b"FINS":
        raise ValueError("invalid FINS/TCP header")
    length = int.from_bytes(header[4:8], "big")
    if length > 65_527:
        raise ValueError("oversized FINS/TCP request")
    return header + await reader.readexactly(length)


async def handle_fins(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = await read_fins_frame(reader)
        if request[8:12] != b"\0\0\0\0":
            return
        writer.write(fins_tcp_frame(1, b"\0\0\0\x0a\0\0\0\x01"))
        await writer.drain()
        request = await read_fins_frame(reader)
        if request[8:12] != b"\0\0\0\x02":
            return
        if os.environ.get("OTTER_FINS_TCP_ERROR") == "1":
            writer.write(b"NOT-FINS")
            await writer.drain()
            return
        payload = bytearray(fins_payload(5))
        payload[3:6], payload[6:9] = request[22:25], request[19:22]
        writer.write(fins_tcp_frame(2, payload))
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


class FinsUdp(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        if len(data) >= 12 and data[10:12] == b"\x05\x01":
            payload = bytearray(fins_payload(data[9]))
            payload[3:6], payload[6:9] = data[6:9], data[3:6]
            self.transport.sendto(payload, address)


FOX_RESPONSE = b"""fox a 0 -1 fox hello
{
hostName=s:niagara-station-1
hostAddress=s:172.30.0.14
fox.version=s:4.13.1
app.name=s:Station
app.version=s:4.13.1
vm.name=s:Java HotSpot
vm.version=s:17
os.name=s:QNX
timeZone=s:Europe/Berlin
hostId=s:OTLAB-FOX-1
vmUuid=s:00000000-0000-0000-0000-000000000014
brandId=s:Tridium
};;
"""


async def handle_fox(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = bytearray()
        while b"};;" not in request and len(request) <= 65_536:
            chunk = await reader.read(2048)
            if not chunk:
                return
            request.extend(chunk)
        if request.startswith(b"fox a 1"):
            writer.write(FOX_RESPONSE)
            await writer.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def run_fins() -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        FinsUdp, local_addr=("0.0.0.0", 9600)
    )
    server = await asyncio.start_server(handle_fins, "0.0.0.0", 9600)
    try:
        async with server:
            await server.serve_forever()
    finally:
        transport.close()


async def run_fox() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/lab.crt", "/lab.key")
    plain = await asyncio.start_server(handle_fox, "0.0.0.0", 1911)
    tls = await asyncio.start_server(handle_fox, "0.0.0.0", 4911, ssl=context)
    http = await asyncio.start_server(handle_http, "0.0.0.0", 80)
    https = await asyncio.start_server(handle_http, "0.0.0.0", 443, ssl=context)
    async with plain, tls, http, https:
        await asyncio.gather(*(server.serve_forever() for server in (plain, tls, http, https)))


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        assert request.startswith(b"GET / HTTP/1.1\r\n"), request
        assert b"authorization:" not in request.lower(), request
        tls = writer.get_extra_info("ssl_object") is not None
        status = b"503 Service Unavailable" if tls else b"200 OK"
        body = b"<html><head><TITLE>Niagara &amp; Web Panel</TITLE></head></html>"
        writer.write(b"HTTP/1.1 " + status + b"\r\nServer: OT-Lab-Web/1.0\r\n"
                     b"Content-Type: text/html\r\nConnection: close\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


DNP3_ADDRESS = 1
DNP3_PORT = 20000
DNP3_READ_ATTRIBUTES = bytes.fromhex("C0C00100FE06")


def dnp3_crc(data: bytes) -> int:
    """CRC-16/DNP: reflected polynomial 0xA6BC, zero seed, inverted result."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def dnp3_append_crc(data: bytes) -> bytes:
    crc = dnp3_crc(data)
    return data + bytes([crc & 0xFF, crc >> 8])


def dnp3_frame(control: int, destination: int, source: int, data: bytes = b"") -> bytes:
    """Link frame: the length octet counts control, addresses, and user data but no checksums."""
    header = (
        bytes([0x05, 0x64, 5 + len(data), control])
        + destination.to_bytes(2, "little")
        + source.to_bytes(2, "little")
    )
    frame = dnp3_append_crc(header)
    for index in range(0, len(data), 16):
        frame += dnp3_append_crc(data[index : index + 16])
    return frame


def dnp3_attribute(variation: int, data_type: int, value: bytes) -> bytes:
    """One Group 0 device attribute: header, 8-bit count of one, data type, length, value."""
    return bytes([0x00, variation, 0x00, 0, 0, data_type, len(value)]) + value


# IEEE 1815 visible strings use datatype 1. Type 254 is an attribute list, not text.
DNP3_ATTRIBUTES = b"".join(
    [
        dnp3_attribute(196, 1, b"0A1B2C3D"),
        dnp3_attribute(197, 1, b"2.0"),
        dnp3_attribute(202, 1, b"otlab-dnp3-mrid-0001"),
        dnp3_attribute(208, 1, b"OT Lab SCADA"),
        dnp3_attribute(240, 2, (292).to_bytes(2, "little")),
        dnp3_attribute(241, 2, (292).to_bytes(2, "little")),
        dnp3_attribute(242, 1, b"4.2.1"),
        dnp3_attribute(243, 1, b"rev C"),
        dnp3_attribute(244, 1, b"OT Lab Operations"),
        dnp3_attribute(245, 1, b"OT Lab / Cell 2"),
        dnp3_attribute(246, 1, b"OTLAB-DNP3-1"),
        dnp3_attribute(247, 1, b"dnp3-outstation-1"),
        dnp3_attribute(248, 1, b"DNPLAB0001"),
        dnp3_attribute(249, 2, (3).to_bytes(1, "little")),
        dnp3_attribute(250, 1, b"OT Lab RTU 3000"),
        dnp3_attribute(252, 1, b"OT Lab Automation"),
    ]
)


def dnp3_segments(payload: bytes) -> list[bytes]:
    """Splits an application fragment into transport frames of at most 249 payload octets."""
    chunks = [payload[index : index + 249] for index in range(0, len(payload), 249)]
    segments = []
    for index, chunk in enumerate(chunks):
        control = (0x40 if index == 0 else 0) | (0x80 if index == len(chunks) - 1 else 0)
        segments.append(bytes([control | (index & 0x3F)]) + chunk)
    return segments


class Dnp3Outstation:
    """Read-only outstation: link reset, then a Group 0 device attribute read."""

    def __init__(self, address: int = DNP3_ADDRESS) -> None:
        self.address = address
        self.reset = False
        self.next_fcb = False

    def respond(self, source: int, objects: bytes, iin2: int = 0) -> list[bytes]:
        application = bytes([0xC0, 0x81, 0x02, iin2]) + objects
        return [
            dnp3_frame(0x04, source, self.address, segment)
            for segment in dnp3_segments(application)
        ]

    def handle(self, control: int, destination: int, source: int, data: bytes) -> list[bytes]:
        if destination != self.address:
            return []
        ack = dnp3_frame(0x00, source, self.address)
        function = control & 0x0F
        if function == 0x00:
            self.reset = True
            self.next_fcb = False
            return [ack]
        if function != 0x03:
            return [dnp3_frame(0x0F, source, self.address)]
        if not self.reset or bool(control & 0x20) != self.next_fcb:
            return [ack]
        self.next_fcb = not self.next_fcb
        if data[1:6] == DNP3_READ_ATTRIBUTES[1:]:
            return [ack, *self.respond(source, DNP3_ATTRIBUTES)]
        return [ack, *self.respond(source, b"", iin2=0x02)]


async def read_dnp3_frame(reader: asyncio.StreamReader) -> tuple[int, int, int, bytes]:
    header = await reader.readexactly(8)
    if header[:2] != b"\x05\x64":
        raise ValueError("invalid DNP3 start bytes")
    data_length = header[2] - 5
    if data_length < 0:
        raise ValueError("truncated DNP3 frame")
    blocks = -(-data_length // 16)
    body = await reader.readexactly(2 + data_length + 2 * blocks)
    if dnp3_crc(header) != int.from_bytes(body[:2], "little"):
        raise ValueError("invalid DNP3 header checksum")
    data = bytearray()
    cursor = 2
    while cursor < len(body):
        block = body[cursor : cursor + min(16, data_length - len(data))]
        cursor += len(block)
        if dnp3_crc(block) != int.from_bytes(body[cursor : cursor + 2], "little"):
            raise ValueError("invalid DNP3 data checksum")
        cursor += 2
        data += block
    return (
        header[3],
        int.from_bytes(header[4:6], "little"),
        int.from_bytes(header[6:8], "little"),
        bytes(data),
    )


async def handle_dnp3(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    outstation = Dnp3Outstation()
    try:
        while True:
            for reply in outstation.handle(*await read_dnp3_frame(reader)):
                writer.write(reply)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        # A master stops reading once it has its response, so the close can race a reset.
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def run_dnp3() -> None:
    server = await asyncio.start_server(handle_dnp3, "0.0.0.0", DNP3_PORT)
    async with server:
        await server.serve_forever()


def self_test() -> None:
    udp = fins_payload(0xEF)
    tcp = fins_tcp_frame(2, fins_payload(5))
    assert len(udp) == 106 and udp[9:14] == b"\xef\x05\x01\0\0"
    assert len(tcp) == 122 and tcp[:4] == b"FINS"
    assert tcp[16] == 0xC0 and tcp[25:30] == b"\x05\x05\x01\0\0"
    assert FOX_RESPONSE.startswith(b"fox a 0") and FOX_RESPONSE.endswith(b"};;\n")
    server_info = struct.pack("<III", ADS_COOKIE, 0, 1) + bytes(12)
    assert ads_server_info_response(server_info)[12:18] == ADS_NET_ID
    request_header = (
        ADS_NET_ID
        + (851).to_bytes(2, "little")
        + bytes([172, 30, 0, 2, 1, 1])
        + (32768).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + (4).to_bytes(2, "little")
        + bytes(8)
        + (9).to_bytes(4, "little")
    )
    ads_reply = ads_response(b"\0\0" + (32).to_bytes(4, "little") + request_header)
    assert int.from_bytes(ads_reply[22:24], "little") == 1
    assert ads_reply[38:42] == bytes(4)
    assert ads_reply[42:46] == bytes([3, 1, 0xB5, 0x0F])

    # Published opendnp3 link vectors, then the scanner's pipelined cold start.
    assert dnp3_frame(0xC0, 1, 1024) == bytes.fromhex("056405C001000004E921")
    assert dnp3_frame(0x00, 1024, 1) == bytes.fromhex("056405000004010019A6")
    assert dnp3_frame(0xD3, 1, 1, DNP3_READ_ATTRIBUTES) == bytes.fromhex(
        "05640BD301000100426DC0C00100FE065DB9"
    )
    outstation = Dnp3Outstation()
    assert outstation.handle(0xD3, 2, 1, DNP3_READ_ATTRIBUTES) == []
    assert outstation.handle(0xD3, 1, 1, DNP3_READ_ATTRIBUTES) == [dnp3_frame(0x00, 1, 1)]
    assert outstation.handle(0xC0, 1, 1, b"") == [dnp3_frame(0x00, 1, 1)]
    replies = outstation.handle(0xD3, 1, 1, DNP3_READ_ATTRIBUTES)
    assert [reply[3] for reply in replies] == [0x00, 0x04, 0x04]
    assert len(replies[1]) == 292 and replies[1][2] == 255
    assert outstation.handle(0xD3, 1, 1, DNP3_READ_ATTRIBUTES) == [dnp3_frame(0x00, 1, 1)]
    unknown = outstation.handle(0xF3, 1, 1, bytes.fromhex("C0C0011E0107"))
    assert [reply[3] for reply in unknown] == [0x00, 0x04]
    assert unknown[-1][10:15] == bytes([0xC0, 0xC0, 0x81, 0x02, 0x02])


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "self-test":
        self_test()
    elif mode == "fins":
        asyncio.run(run_fins())
    elif mode == "fox":
        asyncio.run(run_fox())
    elif mode == "dnp3":
        asyncio.run(run_dnp3())
    elif mode == "ads":
        asyncio.run(run_ads())
    else:
        raise SystemExit("usage: responders.py {fins|fox|dnp3|ads|self-test}")
