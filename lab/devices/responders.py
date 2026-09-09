#!/usr/bin/env python3
"""Small read-only responders for protocols without maintained test emulators."""

import asyncio
import ssl
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
        writer.write(fins_tcp_frame(2, fins_payload(5)))
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
            self.transport.sendto(fins_payload(0xEF), address)


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
    async with plain, tls:
        await asyncio.gather(plain.serve_forever(), tls.serve_forever())


DNP3_ADDRESS = 1
DNP3_PORT = 20000
DNP3_READ_ATTRIBUTES = bytes.fromhex("C0C001000006")


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
    return bytes([0x00, variation, 0x07, 0x01, data_type, len(value)]) + value


# Vendors disagree on the string data type code, so the lab reports most attributes as 254 and the
# hardware version as 1 to prove the scanner decodes both conventions.
DNP3_ATTRIBUTES = b"".join(
    [
        dnp3_attribute(196, 254, b"0A1B2C3D"),
        dnp3_attribute(197, 254, b"2.0"),
        dnp3_attribute(202, 254, b"otlab-dnp3-mrid-0001"),
        dnp3_attribute(208, 254, b"OT Lab SCADA"),
        dnp3_attribute(240, 2, (292).to_bytes(2, "little")),
        dnp3_attribute(241, 2, (292).to_bytes(2, "little")),
        dnp3_attribute(242, 254, b"4.2.1"),
        dnp3_attribute(243, 1, b"rev C"),
        dnp3_attribute(244, 254, b"OT Lab Operations"),
        dnp3_attribute(245, 254, b"OT Lab / Cell 2"),
        dnp3_attribute(246, 254, b"OTLAB-DNP3-1"),
        dnp3_attribute(247, 254, b"dnp3-outstation-1"),
        dnp3_attribute(248, 254, b"DNPLAB0001"),
        dnp3_attribute(249, 2, (3).to_bytes(1, "little")),
        dnp3_attribute(250, 254, b"OT Lab RTU 3000"),
        dnp3_attribute(252, 254, b"OT Lab Automation"),
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

    # Published opendnp3 link vectors, then the scanner's pipelined cold start.
    assert dnp3_frame(0xC0, 1, 1024) == bytes.fromhex("056405C001000004E921")
    assert dnp3_frame(0x00, 1024, 1) == bytes.fromhex("056405000004010019A6")
    assert dnp3_frame(0xD3, 1, 1, DNP3_READ_ATTRIBUTES) == bytes.fromhex(
        "05640BD301000100426DC0C001000006E366"
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
    else:
        raise SystemExit("usage: responders.py {fins|fox|dnp3|self-test}")
