# PROFINET I&M Record Network Scan

## Purpose

This document describes how a separate network-scanning tool can discover PROFINET devices and read the Identification and Maintenance records used by Proneta.

The relevant application objects are:

- `Device.IMRecord`: the I&M data associated with the primary device module.
- `Device.Modules[*].IMRecord`: I&M data associated with an individual module.
- `IMData`: the common data model for I&M0 through I&M5.

The main `SoftwareRevision` value is read from the PROFINET I&M0 record. It is not calculated during XML export and it is not the PRONETA application version.

## Protocol

The scan requires PROFINET acyclic record reads using the PNIO DCE/RPC read-record mechanism. DCP discovery alone is not sufficient.

The request must identify the target using:

| Field | Type | Meaning |
|---|---:|---|
| `Api` | `uint32` | Application Process Identifier. |
| `Slot` | `uint16` | Module slot number. |
| `Subslot` | `uint16` | Target subslot number. |
| `Index` | `uint16` | PROFINET record index. |
| `DataLength` | `uint32` | Maximum response length requested by the client. |

Use the network endpoint discovered for the device: MAC address, IP address, subnet mask, and station name as required by the PNIO stack. The implementation must support fragmented or multi-part record responses and reassemble the complete record before parsing it.

The Proneta generic record-request builder defaults to a maximum data length of `32768` bytes. A different PNIO stack may choose another value, but it must still support records larger than one Ethernet frame.

For its non-supervisor automatic reads, the decompiled request defaults are:

| Parameter | Default |
|---|---|
| `UseSupervisorAr` | `false`; the request is sent as a PNIO implicit read. |
| `ArUuid` | `ffddee11-b010-c020-e010-116655443322` in the high-level read parameters. The implicit-read handler does not copy it into the packet; the implicit packet builder starts with an all-zero wire `ArUuid`. |
| `TargetArUuid` | `00000000-0000-0000-0000-000000000000` in the scanner handler. Set it explicitly when reading through an existing AR. |
| `KeepConnection` | `true`. |
| `ProcessResponse` | `true`. |

These are layered Proneta/SISL defaults. The standalone `ReadImplicitRequestParametersBuilder` has a different `TargetArUuid` default (`ffddee11-b010-c020-e010-116655443322`), while `ReadRecordRequestHandler` constructs `ReadImplicitRequestParameters` directly. A new tool should use the equivalent settings required by its PNIO communication library rather than assuming that these UUID values are universal device requirements.

## Wire-Level Record Read

The logical `read_record(endpoint, Api, Slot, Subslot, Index)` operation is sent as:

```text
Ethernet II
  IPv4
    UDP
      DCE/RPC request
        PNIO ReadImplicit stub
          IOD ReadReq header
```

The following describes the packet built by Proneta's non-supervisor path. It is more precise than saying only "send a PNIO read" and is the minimum information a raw-packet scanner must reproduce.

### 1. Resolve the RPC endpoint

If the device's RPC endpoint is not cached, Proneta performs an Endpoint Mapper (EPM) exchange before the record read. DCP provides the device address, but it does not provide the PNIO RPC object and interface values needed by the read packet.

The modern EPM request is:

```text
Ethernet II -> IPv4 -> UDP source 34964, destination 34964 -> DCE/RPC EPM Read
```

The EPM request builder uses these values:

| Field | Value |
|---|---|
| RPC version | `4` |
| RPC packet type | `REQUEST` |
| RPC operation | `Read` (`2`) |
| EPM interface UUID | `dea00001-6c97-11d1-8271-00a02442df7d` |
| Object UUID | all zeroes |
| RPC interface version | `3` |
| EPM map version | `1.0` |
| RPC flags | `Flags1 = 0x20` |

The legacy EPM path uses source UDP port `63267` and an all-zero EPM interface UUID. If the EPM response returns a non-default handle, the stack sends another EPM request using that handle.

Use the EPM response to cache, per device:

- RPC endianness/data representation.
- PNIO object UUID.
- PNIO interface UUID.
- Target UDP port. Proneta falls back to `34964` when the returned port is zero.
- The returned EPM handle for any follow-up lookup.

### 2. Build the PNIO read packet

The record request is built with these outer layers:

| Layer | Request value |
|---|---|
| Ethernet destination | Device MAC from discovery/EPM station data. |
| IPv4 destination | Device IP address. |
| UDP source port | `34964`. |
| UDP destination port | EPM-resolved target port, normally `34964`. |
| RPC version | `4`. |
| RPC packet type | `REQUEST`. |
| RPC flags | `Flags1 = 0x20`. |
| RPC interface version | `1`. |
| RPC operation | `ReadImplicit` (`5`). |
| RPC fragment length | `84` bytes for the PNIO read stub. |
| RPC object/interface UUID | Values learned from EPM. |
| RPC activity UUID | Proneta's predefined activity UUID for the destination MAC, or the activity UUID for a resolved AR when `TargetArUuid` is non-zero. |
| RPC endianness | The representation learned from EPM. |

The PNIO read stub contains the NDR-style arguments followed by a 64-byte `PnioReadReqHeader`:

| Stub field | Value |
|---|---|
| `ArgsMaximum` | `DataLength + 64`. |
| `ArgsLength` | `64`. |
| Array maximum count | `DataLength + 64`. |
| Array offset | `0`. |
| Array actual count | `64`. |
| Payload after header | Empty for a read request. |

The outer `ArgsMaximum`, `ArgsLength`, and array values use the RPC data representation. The PNIO IOD header fields are written big-endian.

### 3. Encode the IOD ReadReq header

Offsets below are relative to the start of `PnioReadReqHeader`, not the Ethernet or RPC packet:

| Offset | Size | Field | Value |
|---:|---:|---|---|
| `0` | `6` | IOD block header | Block type `0x0009`, block length `60`, version `1.0`. |
| `6` | `2` | `SeqNumber` | `0` in Proneta's request builder. This is separate from the RPC sequence number. |
| `8` | `16` | `ArUuid` | All zeroes in the actual `ReadImplicitPacketBuilder` path. |
| `24` | `4` | `Api` | Requested API. |
| `28` | `2` | `SlotNumber` | Requested module slot. |
| `30` | `2` | `SubslotNumber` | Requested subslot. |
| `32` | `2` | Reserved | Zero. |
| `34` | `2` | `Index` | `0xF821`, `0xF840`, `0xF000`, or `0xAFF0`-`0xAFF5`, as applicable. |
| `36` | `4` | `RecordDataLength` | Maximum record bytes requested, normally `32768`. A zero value is serialized by the builder as `4004`. |
| `40` | `16` | `TargetArUuid` | Zero for the ordinary scanner path; use the requested AR UUID when reading through an existing AR. |
| `56` | `8` | Reserved | Zero. |

The six-byte IOD block header's length is `60`; the complete request header occupies `64` bytes because the four-byte type/length prefix is not included in the PNIO block length.

### 4. Receive and reassemble the response

Match the UDP response to the request using the RPC sequence number. Proneta's `ReadImplicitPhase` stores responses in a request table and compares packets with `CompareByRpcSequenceNumber`.

For a fragmented response:

1. Store each RPC response fragment in fragment-number order.
2. When the response has the RPC fragment flag and does not have `NoFack`, send a DCE/RPC `FACK` to the same device and target UDP port.
3. The FACK repeats the request's object UUID, interface UUID, activity UUID, and `ReadImplicit` operation. It carries the last response fragment number and RPC sequence number.
4. Continue until the RPC last-fragment flag is received.
5. Merge the RPC fragments before parsing the PNIO response stub.

Proneta's fragment logic assumes roughly `1350` record-data bytes per fragment when determining whether all requested data has arrived. A new tool should use the actual RPC fragment flags and lengths rather than assuming that every record fits in one UDP datagram.

### 5. Parse the PNIO read response

After RPC fragment reassembly, parse `PnioImplicitReadResponse` from the RPC stub:

| Offset | Size | Field |
|---:|---:|---|
| `0` | `4` | PNIO status, using the RPC data representation. |
| `4` | `4` | `ArgsLength`. |
| `8` | `12` | PNIO array: maximum count, offset, actual count. |
| `20` | `64+` | IOD read response header and record data. |
| `84` | variable | Record data starts here in the response stub. |

The response IOD header uses the following offsets relative to offset `20`:

| Offset | Size | Field |
|---:|---:|---|
| `0` | `6` | IOD block header; the response block type is `0x8009`. |
| `6` | `2` | Response sequence number. |
| `8` | `16` | AR UUID. |
| `24` | `4` | API. |
| `28` | `2` | Slot number. |
| `30` | `2` | Subslot number. |
| `32` | `2` | Reserved. |
| `34` | `2` | Record index. |
| `36` | `4` | `RecordDataLength`. |
| `40` | `2` | Additional value 1. |
| `42` | `2` | Additional value 2. |
| `64` | variable | Record bytes. |

Reject a response when the PNIO status is an error, the response block type is not `0x8009`, the echoed API/slot/subslot/index does not match the request, or the captured bytes are shorter than `RecordDataLength`. Proneta's packet parser treats status value `50331932` as an error; a new implementation should decode the `PnioCmStatus` fields instead of depending only on that implementation constant.

The record bytes at response-stub offset `84` are then parsed as the requested record. They start with that record's own six-byte IOD block header, followed by the I&M/API/module payload described in the rest of this document.

### Minimal read loop

```text
endpoint = dcp_identify(device)
if endpoint.rpc_info is missing:
    endpoint.rpc_info = epm_lookup(endpoint)

for target in record_targets(endpoint):
    request = build_ethernet_ipv4_udp_rpc_read_implicit(
        endpoint=endpoint,
        api=target.api,
        slot=target.slot,
        subslot=target.subslot,
        index=target.index,
        data_length=32768
    )
    send(request)
    fragments = receive_matching_rpc_fragments(request)
    send_facks_when_required(fragments)
    response = merge_rpc_fragments(fragments)
    record = parse_successful_pnio_read_response(response)
    parse_record_payload(record)
```

## Discovery Sequence

The following sequence mirrors the relevant Proneta scanner phases.

### 1. Discover devices

Use PROFINET DCP Identify to obtain at least:

- MAC address
- IP address and subnet mask
- station name
- device/vendor identity when available

The scan can include controllers, but the Proneta scanner normally excludes interfaces handled as controllers from the ordinary device/module I&M read loop. A general-purpose tool should make this a configurable policy instead of silently excluding them.

### 2. Read API data

Read record index `0xF821` (`63521`) from the primary device target.

The response contains the API values supported by the device. The response parser creates one API entry for each returned API.

Use the returned APIs in subsequent reads. Do not assume that API `0` is the only API.

### 3. Read I&M0 filter data

Read record index `0xF840` (`63552`) for each relevant API.

The I&M0 filter response identifies the module and submodule layout relevant to I&M reads. It can contain:

- API values
- module slot numbers
- module identification numbers
- subslot numbers
- submodule identification numbers
- I&M record availability information

Use this response to build a list of valid module targets. It also provides the device's primary I&M slot/subslot configuration when the device does not use the default target.

### 4. Read real identification data

Read record index `0xF000` (`61440`) for each API.

This is used to obtain the actual module and submodule layout:

```text
API
  Module
    SlotNumber
    ModuleIdentNumber
    Submodules
      SubslotNumber
      SubmoduleIdentNumber
```

The module identity record is useful for correlating an I&M response with the physical module, but it does not replace the I&M0 read.

### 5. Read I&M records

For every target `(Api, Slot, Subslot)` that should be inspected:

1. Read I&M0 at index `0xAFF0`.
2. Parse and store the I&M0 fields.
3. Read I&M1 through I&M5 only when the I&M0 support mask says they are supported.
4. Store the results under the same `(Api, Slot, Subslot)` key.

The standard record indices are:

| Record | Index | Hex | Proneta processor |
|---|---:|---:|---|
| I&M0 | `45040` | `0xAFF0` | `Im0RecordProcessor` |
| I&M1 | `45041` | `0xAFF1` | `Im1RecordProcessor` |
| I&M2 | `45042` | `0xAFF2` | `Im2RecordProcessor` |
| I&M3 | `45043` | `0xAFF3` | `Im3RecordProcessor` |
| I&M4 | `45044` | `0xAFF4` | `Im4RecordProcessor` |
| I&M5 | `45045` | `0xAFF5` | `Im5RecordProcessor` |

## Target Addressing

### Primary device target

Proneta obtains the primary target from the I&M record configuration returned by the I&M0 filter data. Its fallback is:

```text
Slot    = 0
Subslot = 1
```

There is one source-specific fallback for device ID `786`, where the default slot is `1`. A new scanner should prefer discovered I&M configuration over this hardcoded fallback.

### Module target

For a module, use:

```text
Api     = module.Api
Slot    = module.SlotNumber
Subslot = the I&M-capable subslot for that module
```

Proneta selects the first submodule subslot for a module. A complete scanner should retain every discovered subslot and query each applicable I&M target, deduplicating requests by `(Api, Slot, Subslot)`.

Do not key module data by slot alone. The same slot number can exist under different APIs, and the complete key is:

```text
(device endpoint, Api, Slot, Subslot)
```

## I&M0 Parsing

The parser uses the six-byte IOD block header followed by the fields below. All numeric values are big-endian.

| Offset | Size | Wire field | Result field | Conversion |
|---:|---:|---|---|---|
| `0` | `6` | IOD block header | `BlockHeader` | PNIO block header. |
| `6` | `2` | Vendor ID | `ManufacturerID` | Big-endian `uint16`, formatted as four hexadecimal digits by Proneta. |
| `8` | `20` | Order ID | `OrderID` | UTF-8 text, cleaned and trimmed. |
| `28` | `16` | Serial number | `SerialNumber` | UTF-8 text, cleaned and trimmed. |
| `44` | `2` | Hardware revision | `HardwareRevision` | Big-endian `uint16`, converted to a decimal string. |
| `46` | `1` | Software revision prefix | `SoftwareRevision` | Usually a letter such as `A`. |
| `47` | `1` | Functional enhancement | `SoftwareRevision` | Decimal component 1. |
| `48` | `1` | Bug fix | `SoftwareRevision` | Decimal component 2. |
| `49` | `1` | Internal change | `SoftwareRevision` | Decimal component 3. |
| `50` | `2` | Revision counter | `RevisionCounter` | Big-endian `uint16`, converted to a decimal string. |
| `52` | `2` | Profile ID | `ProfileID` | Big-endian `uint16`, formatted as four hexadecimal digits by Proneta. |
| `54` | `2` | Profile-specific type | `ProfileDetails` | Big-endian `uint16`, converted to a decimal string. |
| `56` | `1` | I&M version major | `IMVersion` | Combined with the minor byte as `major.minor`. |
| `57` | `1` | I&M version minor | `IMVersion` | Combined with the major byte. |
| `58` | `2` | Supported I&M records | `IMSupported` | Big-endian bit mask. |

The software revision string is constructed as:

```text
prefix + functionalEnhancement + "." + bugFix + "." + internalChange
```

Example:

```text
Bytes 46..49 = 41 01 02 03
SoftwareRevision = A1.2.3
```

The prefix byte is interpreted as one UTF-8 character. If the prefix is zero in the I&M5 software-revision parser, the result is treated as an empty string.

The fixed-size records have these total lengths in the parser implementation, including the six-byte block header:

| Record | Total length |
|---|---:|
| I&M0 | `60` bytes |
| I&M1 | `60` bytes |
| I&M2 | `22` bytes |
| I&M3 | `60` bytes |
| I&M4 | `60` bytes |

I&M5 is variable-length.

### I&M support mask

The support mask controls the additional requests:

| Mask | Record |
|---:|---|
| `0x0002` | I&M1 |
| `0x0004` | I&M2 |
| `0x0008` | I&M3 |
| `0x0010` | I&M4 |
| `0x0020` | I&M5 |

I&M0 is the base record and is read before evaluating this mask.

`ManufacturerName` is not encoded in the I&M0 payload. Proneta resolves it later from its vendor table using the manufacturer ID.

## I&M1 Parsing

Record index: `0xAFF1`.

| Offset | Size | Wire field | Result field |
|---:|---:|---|---|
| `0` | `6` | IOD block header | `BlockHeader` |
| `6` | `32` | I&M tag function | `Function` |
| `38` | `22` | I&M tag location | `Location` |

Both values are UTF-8 strings. Non-printable characters are replaced with spaces, NUL characters are removed, and the result is trimmed.

## I&M2 Parsing

Record index: `0xAFF2`.

| Offset | Size | Wire field | Result field |
|---:|---:|---|---|
| `0` | `6` | IOD block header | `BlockHeader` |
| `6` | `16` | I&M installation date | `InstallationDate` |

The value is handled as a trimmed UTF-8 text field. Proneta does not convert it to a date object.

## I&M3 Parsing

Record index: `0xAFF3`.

| Offset | Size | Wire field | Result field |
|---:|---:|---|---|
| `0` | `6` | IOD block header | `BlockHeader` |
| `6` | `54` | I&M descriptor | `Descriptor` |

The descriptor is handled as cleaned, trimmed UTF-8 text.

## I&M4 Parsing

Record index: `0xAFF4`.

The parser reads a 54-byte signature area after the six-byte block header. It parses the check fields only when the first four bytes are `0x63 0x72 0x63 0x31` (`"crc1"`). It then parses the following big-endian `uint32` values:

| Offset | Size | Result field |
|---:|---:|---|
| `6` | `4` | `UserStructureIdentifier` |
| `10` | `4` | `CheckOverall` |
| `14` | `4` | `CheckOverallSubs` |
| `18` | `4` | `CheckStaticLocal` |
| `22` | `4` | `CheckStaticSubs` |
| `26` | `4` | `CheckOverallSetup` |
| `30` | `4` | `CheckRemanentLocal` |
| `34` | `4` | `CheckRemanentSubs` |
| `38` | `4` | `CheckWorkingLocal` |
| `42` | `4` | `CheckWorkingSubs` |

The complete raw 54-byte area is also retained as `ImSignature`.

Proneta skips the I&M4 processor when the parsed record is empty. In the Proneta domain model, `IMData.Im4Info` is marked `XmlIgnore`, so a normal Proneta topology XML export does not contain this I&M4 object even though the scanner reads it in memory.

## I&M5 Parsing

Record index: `0xAFF5`.

I&M5 is a variable-length record. After the six-byte block header, the parser reads:

```text
uint16 NumberOfEntries at offset 6
```

It then iterates the embedded IOD blocks. The implementation recognizes:

| Block type | Meaning |
|---:|---|
| `52` (`0x34`) | I&M5 data entry |
| `54` (`0x36`) | Full asset-management block |
| `55` (`0x37`) | Hardware-only asset-management block |
| `56` (`0x38`) | Firmware-only asset-management block |

Each embedded block advances by:

```text
blockHeader.BlockLength + 4
```

### I&M5 data entry

The I&M5 data block contains:

| Offset | Size | Result field |
|---:|---:|---|
| `6` | `64` | `ImAnnotation` |
| `70` | `64` | `ImOrderId` |
| `134` | `2` | `VendorId` |
| `136` | `16` | `ImSerialNumber` |
| `152` | `2` | `ImHardwareRevision` |
| `154` | `4` | `ImSoftwareRevision` |

The four-byte I&M5 software revision uses the same format as I&M0:

```text
prefix, functional enhancement, bug fix, internal change
```

The resulting domain object is `IMData.Im5Info.Im5Data[*]`.

### Asset-management block

Each asset-management block is represented as `IMData.Im5Info.AmBlocks[*]`.

Common fields exposed by Proneta are:

| Result field | Meaning |
|---|---|
| `ImUniqueIdentifier` | RPC object UUID identifying the asset. |
| `AmLocation` | Asset location. |
| `ImAnnotation` | I&M annotation text. |
| `ImOrderId` | I&M order ID. |
| `AmSoftwareRevision` | Asset-management software revision text. |
| `AmHardwareRevision` | Asset-management hardware revision text, when present. |
| `ImSerialNumber` | I&M serial number. |
| `ImSoftwareRevision` | Four-byte I&M-style software revision. |
| `AmDeviceIdentification` | Organization, vendor ID, device ID, and device sub-ID. |
| `AmTypeIdentification` | Asset type identification. |
| `ImHardwareRevision` | Numeric I&M hardware revision, when present. |

`AmDeviceIdentification` contains:

| Field | Wire size |
|---|---:|
| `Organization` | `uint16` |
| `VendorId` | `uint16` |
| `DeviceId` | `uint16` |
| `DeviceSubId` | `uint16` |

`AmLocation` can be encoded in one of two structures:

- Slot structure: `BeginSlotNumber`, `BeginSubslotNumber`, `EndSlotNumber`, `EndSubslotNumber`.
- Level structure: `Level0` through `Level11`.

The `Structure` field determines which set is valid. Numeric values are big-endian.

## Module Metadata

An I&M record is not the complete module object. Store both the target address and the module identity data.

Recommended module result fields are:

| Field | Source |
|---|---|
| `Api` | API used for the record request. |
| `ModuleIndex` / `SlotNumber` | Real identification data. |
| `ModuleIdentNumber` | Real identification data. |
| `Submodules[*].SubslotNumber` | Real identification data. |
| `Submodules[*].SubmoduleIdentNumber` | Real identification data. |
| `IsImRecordAvailable` | I&M0 filter data and successful discovery. |
| `IsImRecordSupported` | Successful I&M0 processing. |
| `IMRecord` | I&M0 through I&M5 data. |

`ModuleName`, `ModuleDesc`, and GSDML-specific display information are not authoritative network I&M values. They may be populated later from a GSDML catalog.

The module `OrderNumber` and `SerialNumber` displayed by Proneta are also synchronized from the module's I&M data when the module receives an I&M record.

## Complete Scan Algorithm

The following pseudocode describes a complete scan rather than the reduced default module behavior.

```text
for device in dcp_identify_all():
    endpoint = device.network_endpoint

    apis = read_api_data(
        endpoint=endpoint,
        api=0,
        slot=primary_slot(device),
        subslot=primary_subslot(device),
        index=0xF821
    )

    if apis is empty:
        apis = [0]

    targets = set()

    for api in apis:
        filter_data = read_record(
            endpoint=endpoint,
            api=api,
            slot=primary_slot(device),
            subslot=primary_subslot(device),
            index=0xF840
        )

        real_identification = read_record(
            endpoint=endpoint,
            api=api,
            slot=primary_slot(device),
            subslot=primary_subslot(device),
            index=0xF000
        )

        # Proneta addresses the primary device I&M record with API 0.
        targets.add((0, primary_slot(device), primary_subslot(device)))

        for module in union(filter_data.modules, real_identification.modules):
            for submodule in module.submodules:
                targets.add((api, module.slot, submodule.subslot))

    for target in targets:
        im0 = read_record(
            endpoint=endpoint,
            api=target.api,
            slot=target.slot,
            subslot=target.subslot,
            index=0xAFF0
        )

        if im0 failed:
            store_target_error(target, "I&M0 unavailable")
            continue

        result = parse_im0(im0)

        supported = result.IMSupported
        for bit, index, parser in [
            (0x0002, 0xAFF1, parse_im1),
            (0x0004, 0xAFF2, parse_im2),
            (0x0008, 0xAFF3, parse_im3),
            (0x0010, 0xAFF4, parse_im4),
            (0x0020, 0xAFF5, parse_im5),
        ]:
            if (supported & bit) != 0:
                record = read_record(
                    endpoint=endpoint,
                    api=target.api,
                    slot=target.slot,
                    subslot=target.subslot,
                    index=index
                )
                if record succeeded:
                    result.merge(parser(record))
                else:
                    result.record_errors[index] = "read failed"

        save_im_result(endpoint, target, result)
```

## Proneta-Specific Module Caveat

The decompiled Proneta scanner does the following for its normal scan:

- Reads I&M0 for the device target.
- Uses the I&M0 support mask to chain I&M1 through I&M5 for that device target.
- Reads I&M0 for each additional module using the module API, slot, and first submodule subslot.
- Does not chain I&M1 through I&M5 for those additional module reads because the module read callback only completes the request cycle.

Therefore, a tool that must return every I&M entry for every module must explicitly issue I&M1 through I&M5 for each module target. Do not copy the module loop without adding this step.

## Text and Numeric Conversion Rules

Implement the following conversions for compatibility with the decompiled code:

- Numeric record fields are big-endian.
- I&M0, I&M1, I&M2, and I&M3 text is decoded as UTF-8.
- Text is restricted to printable ASCII (`0x20` through `0x7E`) by the main I&M parsers.
- NUL characters are removed and text is trimmed.
- I&M0 `ManufacturerID` and `ProfileID` are represented by Proneta as four-digit hexadecimal strings.
- I&M0 `HardwareRevision`, `RevisionCounter`, and `ProfileDetails` are represented as decimal strings.
- Software revisions are not endian numeric values. They are four separate bytes formatted as `Pnn.nn.nn`, where `P` is the prefix character.
- Preserve the raw record bytes in the scanner result so parsing can be audited or corrected later.

## Error Handling

The scanner should distinguish these cases:

1. Device not discovered: no DCP response.
2. Record not supported: PNIO error response for the requested index.
3. Target not valid: wrong API, slot, or subslot.
4. Malformed record: response received but block length or payload is invalid.
5. Partial I&M data: I&M0 succeeded but one or more optional records failed.

Do not replace a failed I&M0 read with a GSDML firmware value. GSDML describes configured/catalog data and is not the device's live I&M0 value.

Optional fallbacks used by Proneta are separate from the I&M record path:

- SNMP `sysDescr` can provide a parsed software version for devices without usable I&M data.
- Siemens EPM annotation can provide a fallback version for specific Siemens devices.
- AML and STEP 7 imports can populate `SoftwareRevision` from file attributes.

Mark fallback values with their source; they are not equivalent to a successful I&M0 response.

## XML Compatibility Notes

Proneta exports a `Topology` object with `XmlSerializer`. The export operation does not perform a network request.

For compatibility with the in-memory scan model:

- `IMData.SoftwareRevision` is the primary I&M0 software revision.
- `IMData.Im5Info.Im5Data[*].ImSoftwareRevision` is an I&M5 entry revision.
- `IMData.Im5Info.AmBlocks[*].ImSoftwareRevision` is an asset-management I&M revision.
- `IMData.Im4Info` is marked `XmlIgnore` in the Proneta domain model and is therefore not included in the normal topology XML export.
- `Im5Info` is serialized only when it contains I&M5 data or asset-management blocks.
- Computed properties such as `IsIm1Supported` are not serialized; recalculate them from `IMSupported`.

For a new tool, store the raw records and a normalized structure keyed by `(device endpoint, Api, Slot, Subslot)`. This preserves all information even when the output format differs from Proneta's XML.

## Decompiled Source References

The behavior described above comes from these assemblies in the installation:

- `Libs/net48/Sisl.Scanner.dll`
  - `NetworkScanner`
  - `ReadImplicitProcessor`
  - `ScannerPhases.Phases.ReadImRecordsPhase`
  - `ScannerPhases.Factories.ScannerPhasesFactory`
- `Libs/net48/Sisl.Scanner.Processing.dll`
  - `ProcessingHandlersFactory`
  - `DataProcessors.Processors.Records.Im0RecordProcessor`
  - `Im1RecordProcessor` through `Im5RecordProcessor`
  - `ApiDataRecordProcessor`
  - `RealIdentificationDataRecordProcessor`
- `Libs/net48/PcapDotNet.Packets.dll`
  - `PnioCm.Im0Record` through `PnioCm.Im5Record`
  - `PnioCm.Im5Data`
  - `PnioCm.AssetManagementBlock`
- `Libs/net48/Proneta.Domain.dll`
  - `Device`
  - `Module`
  - `IMData`
  - `Im4Info`
  - `Im5Info`
- `Libs/net48/Sisl.Network.Profinet.dll`
- `EpmCheckPhase`
  - `ReadImplicitPhase`
  - `PnioFragResponseBasePhase`
  - `ReadImplicitRequestParameters`
  - `ReadImplicitRequestParametersBuilder`
- `Libs/net48/Sisl.Network.Communication.dll`
  - `EpmPacketBuilder`
  - `ReadImplicitPacketBuilder`
  - `ReadImplicitLayerBuilder`
  - `PnioReadReqHeaderBuilder`
  - `RpcAckPacketBuilder`
- `Libs/net48/PcapDotNet.Packets.dll`
  - `PnioReadReqHeader`
  - `PnioImplicitReadResponse`
  - `IodReadResHeader`
  - `PnioCmStatus`
  - `RpcOperation`
