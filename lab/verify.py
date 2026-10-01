#!/usr/bin/env python3
"""Run OTserver Otter against the lab and assert its public JSON contract."""

import json
import os
import subprocess
import uuid
from pathlib import Path

SCANNER = "/usr/local/bin/otserver-otter"
SCANNER_CONFIG = Path("/usr/local/bin/otter.json")
ARTIFACTS = Path("/artifacts")
SCANNER_MAC = "02:00:00:00:00:02"
DEVICES = {
    "siemens": "02:00:00:00:00:10",
    "ethernet_ip": "02:00:00:00:00:11",
    "bacnet": "02:00:00:00:00:12",
    "fins": "02:00:00:00:00:13",
    "fox": "02:00:00:00:00:14",
    "opcua": "02:00:00:00:00:15",
    "dnp3": "02:00:00:00:00:16",
    "iec61850": "02:00:00:00:00:17",
    "netbios": "02:00:00:00:00:18",
}
TARGETS = [f"172.30.0.{number}" for number in range(10, 19)]


def run(*arguments: str) -> None:
    command = [SCANNER, *arguments]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def set_snmp(settings: dict) -> None:
    SCANNER_CONFIG.write_text(json.dumps({"snmp": settings}), encoding="utf-8")


def scan(output: Path, targets: list[str], *flags: str) -> dict:
    arguments = ["scan"]
    for target in targets:
        arguments.extend(("--target", target))
    arguments.extend(
        (
            "--interface",
            "eth0",
            "--source-mac",
            SCANNER_MAC,
            "--output",
            str(output),
            "--ack-authorized",
            *flags,
        )
    )
    run(*arguments)
    run("validate", str(output))
    with output.open(encoding="utf-8") as source:
        return json.load(source)


def by_mac(result: dict, mac: str) -> dict:
    return next(device for device in result["devices"] if device["macAddress"] == mac)


def observation(device: dict, source: str) -> dict:
    return next(value for value in device["observations"] if value["source"] == source)


def assert_full(result: dict) -> None:
    assert result["format"] == "otserver-scan" and result["schemaVersion"] == 2
    assert result["scan"].get("partial", False) is False
    assert result["errors"] == []
    assert {device["macAddress"] for device in result["devices"]} == set(DEVICES.values())

    siemens = by_mac(result, DEVICES["siemens"])
    sources = {item["source"] for item in siemens["observations"]}
    assert {"arp", "profinet-dcp", "s7", "snmp"} <= sources

    dcp = observation(siemens, "profinet-dcp")
    assert dcp["fields"] | {
        "name": "siemens-plc-1",
        "model": "ET 200SP Lab",
        "ipAddress": "172.30.0.10",
        "networkMask": "255.255.255.0",
        "gatewayAddress": "172.30.0.1",
    } == dcp["fields"]
    assert dcp["raw"] | {
        "vendorId": 42,
        "deviceId": 0x1234,
        "aliasName": "port-001.siemens-plc-1",
        "deviceInstance": 0x0102,
        "oemVendorId": 42,
        "oemDeviceId": 0x5678,
        "rsiProperties": 0x003F,
        "protocolProperties": 0x001F,
        "deviceInitiative": 1,
        "configurationDomainName": "ot-lab-domain",
    } == dcp["raw"]

    s7 = observation(siemens, "s7")
    assert s7["fields"]["vendor"] == "Siemens"
    assert s7["fields"]["model"] and s7["fields"]["firmwareVersion"]
    assert s7["raw"]["accessPath"]["destinationTsap"]

    snmp = observation(siemens, "snmp")
    assert snmp["fields"] | {
        "name": "siemens-plc-1",
        "location": "OT Lab / Cell 1",
        "vendor": "Siemens",
        "model": "SIMATIC CPU 315-2 PN/DP",
        "serialNumber": "S7LAB0001",
    } == snmp["fields"]
    interface = next(value for value in siemens["interfaces"] if value["key"] == "ifIndex:1")
    assert interface["macAddress"] == DEVICES["siemens"]
    assert interface["speed"] == 1_000_000_000
    assert interface["adminStatus"] == interface["operStatus"] == "up"
    assert snmp["raw"]["1.0.62439.1.1.1.1.2.1"] == "00112233445566778899AABBCCDDEEFF"
    assert snmp["raw"]["physicalEntities"][0]["serialClaim"]["original"] == "S7LAB0001"
    lldp_port = next(value for value in siemens["ports"] if value["key"] == "lldpPort:1")
    assert lldp_port["vlans"] == [1]
    assert lldp_port["raw"]["lldpDot3"]["maxFrameSize"] == 1500
    assert lldp_port["raw"]["lldpPno"]["portNoS"] == "port-001.siemens-plc-1"
    assert lldp_port["raw"]["lldpPno"]["lpdValue"] == 550
    assert any(
        link["source"] == "lldp"
        and link["local"]["macAddress"] == DEVICES["siemens"]
        and link["remote"]["macAddress"] == DEVICES["ethernet_ip"]
        and link["raw"]["remotePortVlanId"] == 1
        and link["raw"]["remoteDot3"]["maxFrameSize"] == 1500
        and link["raw"]["remotePno"]["portNoS"] == "eth0"
        for link in result["links"]
    )
    pnio = next(
        item
        for item in siemens["observations"]
        if "pnioRecords" in (item.get("raw") or {})
    )
    pnio_records = pnio["raw"]["pnioRecords"]
    assert len(pnio_records) >= 15
    assert {
        "0xF821",
        "0xF840",
        "0xF000",
        "0xAFF0",
        "0xAFF1",
        "0xAFF2",
        "0xAFF3",
        "0xAFF4",
        "0xAFF5",
    } <= {record["index"] for record in pnio_records}
    assert pnio["fields"]["protocols"] == ["profinet", "profinet-pnio"]
    assert (
        pnio["fields"]["manufacturer"]
        == "Chengdu Zongheng Intelligence Control Technology Co., Ltd."
    )

    ethernet_ip = observation(by_mac(result, DEVICES["ethernet_ip"]), "ethernet-ip")
    assert ethernet_ip["fields"] | {
        "name": "OT Lab EtherNet-IP Adapter",
        "model": "OT Lab EtherNet-IP Adapter",
        "vendor": "Rockwell Automation/Allen-Bradley",
        "firmwareVersion": "2.3",
        "serialNumber": "075BCD15",
    } == ethernet_ip["fields"]
    assert ethernet_ip["raw"]["serialClaim"]["scope"] == "adapter"
    assert len(ethernet_ip["raw"]["transportResponses"]) == 2
    enip_ports = {
        (value["key"], value["source"])
        for value in by_mac(result, DEVICES["ethernet_ip"])["ports"]
    }
    assert {("tcp:44818", "ethernet-ip"), ("udp:44818", "ethernet-ip")} <= enip_ports

    bacnet = observation(by_mac(result, DEVICES["bacnet"]), "bacnet")
    assert bacnet["fields"] | {
        "name": "BACnet Basic Device",
        "model": "GNU Basic Server Model 42",
        "description": "BACnet Basic Server Device",
        "location": "GNU Basic Building",
        "vendor": "BACnet Stack at SourceForge",
    } == bacnet["fields"]
    assert bacnet["raw"]["instanceNumber"] == 12001

    fins = observation(by_mac(result, DEVICES["fins"]), "omron-fins")
    assert fins["fields"] | {
        "name": "CJ2M-CPU32",
        "model": "CJ2M-CPU32",
        "vendor": "Omron",
        "firmwareVersion": "02.01",
    } == fins["fields"]
    fins_ports = {value["key"] for value in by_mac(result, DEVICES["fins"])["ports"]}
    assert {"tcp:9600", "udp:9600"} <= fins_ports

    fox = observation(by_mac(result, DEVICES["fox"]), "niagara-fox")
    assert fox["fields"] | {
        "name": "niagara-station-1",
        "operatingSystem": "QNX",
        "vendor": "Tridium",
    } == fox["fields"]
    fox_ports = {value["key"]: value["raw"] for value in by_mac(result, DEVICES["fox"])["ports"]}
    assert fox_ports["tcp:1911"]["tls"] is False
    assert fox_ports["tcp:4911"]["tls"] is True

    dnp3 = observation(by_mac(result, DEVICES["dnp3"]), "dnp3")
    assert dnp3["fields"] | {
        "name": "dnp3-outstation-1",
        "model": "OT Lab RTU 3000",
        "vendor": "OT Lab Automation",
        "firmwareVersion": "4.2.1",
        "serialNumber": "DNPLAB0001",
        "location": "OT Lab / Cell 2",
    } == dnp3["fields"]
    assert dnp3["raw"]["outstationAddress"] == 1
    assert dnp3["raw"]["masterAddress"] == 1
    assert dnp3["raw"]["hardwareVersion"] == "rev C"
    assert dnp3["raw"]["idCode"] == "OTLAB-DNP3-1"
    assert dnp3["raw"]["conformance"] == 3
    assert dnp3["raw"]["iin1"] == "02" and dnp3["raw"]["iin2"] == "00"
    assert dnp3["raw"]["attributes"]["247"] == "dnp3-outstation-1"
    assert dnp3["warnings"] == []
    dnp3_ports = {value["key"] for value in by_mac(result, DEVICES["dnp3"])["ports"]}
    assert "tcp:20000" in dnp3_ports

    iec61850_device = by_mac(result, DEVICES["iec61850"])
    iec61850 = observation(iec61850_device, "iec61850")
    assert iec61850["fields"] | {
        "name": "IEC 61850 Breaker IED",
        "vendor": "OT Lab Automation",
        "model": "IEC 61850 Breaker IED",
        "serialNumber": "IEDLAB0001",
        "hardwareVersion": "HW-2",
        "firmwareVersion": "1.6.2",
        "location": "OT Lab / Substation 1",
        "health": "ok",
        "physicalHealth": True,
        "position": "off",
        "blockedOpen": False,
        "blockedClose": False,
        "operationCount": 42,
    } == iec61850["fields"]
    assert iec61850["raw"]["logicalDevices"] == ["OTTERIEDLD0"]
    logical_nodes = iec61850["raw"]["logicalNodes"]["OTTERIEDLD0"]
    assert set(logical_nodes) == {"LLN0", "LPHD1", "XCBR1"}
    assert "DC$PhyNam$vendor" in logical_nodes["LPHD1"]
    assert "ST$Pos$stVal" in logical_nodes["XCBR1"]
    assert iec61850["raw"]["values"]["OTTERIEDLD0/LPHD1.PhyNam.vendor[DC]"] == "OT Lab Automation"
    assert iec61850["raw"]["values"]["OTTERIEDLD0/LLN0.Health.stVal[ST]"] == 1
    assert iec61850["raw"]["values"]["OTTERIEDLD0/XCBR1.OpCnt.stVal[ST]"] == 42
    assert iec61850["warnings"] == []
    assert iec61850["raw"]["values"]["OTTERIEDLD0/XCBR1.Pos.stVal[ST]"] == {
        "padding": 6,
        "data": "40",
    }
    assert not any("IEC 61850" in warning for warning in result["warnings"])
    iec61850_ports = {value["key"] for value in iec61850_device["ports"]}
    assert "tcp:102" in iec61850_ports

    opcua = observation(by_mac(result, DEVICES["opcua"]), "opc-ua")
    assert opcua["fields"] | {
        "name": "LAB-ASSET-1",
        "vendor": "OT Lab Manufacturing",
        "model": "OPC UA Lab Device",
        "serialNumber": "OPCLAB0001",
        "firmwareVersion": "2.1.0",
        "location": "Plant1/Line3/Cell2",
        "description": "Test Device",
        "status": "online",
    } == opcua["fields"]
    assert "opc-ua" in opcua["fields"].get("protocols", [])
    opcua_ports = {value["key"] for value in by_mac(result, DEVICES["opcua"])["ports"]}
    assert "tcp:4840" in opcua_ports

    netbios_device = by_mac(result, DEVICES["netbios"])
    netbios = observation(netbios_device, "netbios")
    assert netbios["fields"]["name"] == "OTTER-NB"
    assert netbios["fields"]["protocols"] == ["netbios"]
    assert netbios["fields"]["macAddress"] == DEVICES["netbios"]
    assert netbios["raw"]["workgroup"] == "OTLAB"
    assert any(
        name["name"] == "OTTER-NB" and name["suffix"] == 0 and not name["group"]
        for name in netbios["raw"]["names"]
    )
    assert len(netbios["raw"]["unitId"]) == 17
    assert netbios["raw"]["response"]
    assert ("udp:137", "netbios") in {
        (port["key"], port["source"]) for port in netbios_device["ports"]
    }


def assert_v3(result: dict) -> None:
    assert result["errors"] == [] and result["scan"].get("partial", False) is False
    assert len(result["devices"]) == 1
    device = by_mac(result, DEVICES["siemens"])
    snmp = observation(device, "snmp")
    assert snmp["fields"]["name"] == "siemens-plc-1"
    assert snmp["fields"]["serialNumber"] == "S7LAB0001"


def assert_pnio(result: dict) -> None:
    assert result["format"] == "otserver-scan" and result["schemaVersion"] == 2
    assert result["scan"].get("partial", False) is False
    assert result["errors"] == []
    assert len(result["devices"]) == 1
    device = by_mac(result, DEVICES["siemens"])
    pnio = next(
        item
        for item in device["observations"]
        if "pnioRecords" in (item.get("raw") or {})
    )
    records = pnio["raw"]["pnioRecords"]
    assert len(records) >= 15
    assert {
        "0xF821",
        "0xF840",
        "0xF000",
        "0xAFF0",
        "0xAFF1",
        "0xAFF2",
        "0xAFF3",
        "0xAFF4",
        "0xAFF5",
    } <= {record["index"] for record in records}
    assert pnio["fields"]["protocols"] == ["profinet", "profinet-pnio"]
    assert (
        pnio["fields"]["manufacturer"]
        == "Chengdu Zongheng Intelligence Control Technology Co., Ltd."
    )
    by_index = {record["index"]: record["parsed"] for record in records}
    assert by_index["0xF821"]["apis"][0]["api"] == 0
    assert by_index["0xF000"]["apis"][0]["modules"][0]["slot"] == 1
    assert by_index["0xAFF0"]["softwareRevision"] == "V1.2.3"
    assert by_index["0xAFF0"]["imSupported"] == 0x003E
    assert (
        by_index["0xAFF0"]["manufacturerName"]
        == "Chengdu Zongheng Intelligence Control Technology Co., Ltd."
    )
    assert (
        by_index["0xAFF0"]["profileName"]
        == "PROFIBUS: reserved for Device IDs; PROFINET: reserved for Profile IDs"
    )
    assert by_index["0xAFF1"]["function"] == "FUNCTION"
    assert by_index["0xAFF5"]["im5Data"][0]["imSoftwareRevision"] == "V1.2.3"
    assert (
        by_index["0xAFF5"]["im5Data"][0]["vendorName"]
        == "Chengdu Zongheng Intelligence Control Technology Co., Ltd."
    )
    assert len(by_index["0xAFF5"]["assetManagementBlocks"]) == 3


def main() -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:8]
    if os.environ.get("OTTER_PNIO_ONLY") == "1":
        path = ARTIFACTS / f"pnio-{run_id}.otserver.json"
        assert_pnio(
            scan(
                path,
                ["172.30.0.10"],
                "--no-arp",
                "--no-protocols",
                "--no-snmp",
                "--no-lldp",
            )
        )
        os.chmod(path, 0o666)
        print("OTserver Otter PNIO virtual lab passed.", flush=True)
        return
    full_path = ARTIFACTS / f"full-scan-{run_id}.otserver.json"
    v3_path = ARTIFACTS / f"snmp-v3-{run_id}.otserver.json"
    netbios_disabled_path = ARTIFACTS / f"netbios-disabled-{run_id}.otserver.json"
    netbios_unresolved_path = ARTIFACTS / f"netbios-unresolved-{run_id}.otserver.json"
    set_snmp({"version": "2c", "community": "lab-public"})
    assert_full(scan(full_path, TARGETS))
    set_snmp(
        {
            "version": "3",
            "username": "inventory",
            "contextName": "lab-public",
            "authProtocol": "sha256",
            "authPassword": "lab-auth-password",
            "privacyProtocol": "aes128",
            "privacyPassword": "lab-privacy-password",
        }
    )
    assert_v3(
        scan(
            v3_path,
            ["172.30.0.10"],
            "--no-protocols",
            "--no-profinet",
            "--no-lldp",
        )
    )
    netbios_flags = (
        "--no-profinet", "--no-s7", "--no-enip", "--no-bacnet", "--no-fins",
        "--no-fox", "--no-dnp3", "--no-iec61850", "--no-opcua", "--no-snmp", "--no-lldp",
    )
    disabled = scan(netbios_disabled_path, ["172.30.0.18"], *netbios_flags, "--no-netbios")
    disabled_device = by_mac(disabled, DEVICES["netbios"])
    assert not any(item["source"] == "netbios" for item in disabled_device["observations"])
    assert not any(port["source"] == "netbios" for port in disabled_device["ports"])
    unresolved = scan(netbios_unresolved_path, ["172.30.0.18"], *netbios_flags, "--no-arp")
    assert unresolved["devices"] == [] and len(unresolved["unresolved"]) == 1
    netbios = unresolved["unresolved"][0]
    assert netbios["source"] == "netbios" and netbios["fields"]["name"] == "OTTER-NB"
    assert "macAddress" not in netbios and "macAddress" not in netbios["fields"]
    assert netbios["raw"]["subject"]["kind"] == "endpoint"
    assert netbios["raw"]["listeners"][0]["port"] == 137
    for artifact in (full_path, v3_path, netbios_disabled_path, netbios_unresolved_path):
        os.chmod(artifact, 0o666)
    print("OTserver Otter virtual lab passed.", flush=True)


if __name__ == "__main__":
    main()
