//! Active Windows PROFINET DCP through an independently installed Npcap driver.
//!
//! Npcap's `Packet.dll` API is loaded directly from its native System32 subdirectory so an obsolete
//! WinPcap-compatible DLL cannot take precedence.

use std::ffi::{CStr, CString, c_char, c_int, c_uchar, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, HANDLE, HMODULE, SetLastError, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const RECEIVE_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_CAPTURED_FRAMES: usize = 4_096;
const BPF_HEADER_MINIMUM: usize = 18;
const PACKET_ALIGNMENT: usize = 4;

// Public bpf_insn/bpf_program layout from the Npcap SDK's Packet32.h.
#[repr(C)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct BpfProgram {
    length: u32,
    instructions: *mut BpfInsn,
}

// cBPF for `ether[12:2] == 0x8892`: load the etherType, accept PROFINET, drop the rest
// in the driver so a busy segment does not flood the capture path.
const DCP_FILTER: [BpfInsn; 4] = [
    BpfInsn {
        code: 0x28,
        jt: 0,
        jf: 0,
        k: 12,
    },
    BpfInsn {
        code: 0x15,
        jt: 0,
        jf: 1,
        k: 0x8892,
    },
    BpfInsn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0xffff,
    },
    BpfInsn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0,
    },
];

enum Adapter {}

#[repr(C)]
#[derive(Clone, Copy)]
struct OverlappedOffsets {
    offset: u32,
    offset_high: u32,
}

#[repr(C)]
union OverlappedOffset {
    offsets: OverlappedOffsets,
    pointer: *mut c_void,
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: OverlappedOffset,
    event: *mut c_void,
}

/// Public PACKET structure from the Npcap SDK's Packet32.h.
#[repr(C)]
struct Packet {
    event: *mut c_void,
    overlapped: Overlapped,
    buffer: *mut c_void,
    length: u32,
    bytes_received: u32,
    io_complete: c_uchar,
}

type GetAdapterNames = unsafe extern "C" fn(*mut c_char, *mut u32) -> c_uchar;
type GetVersion = unsafe extern "C" fn() -> *const c_char;
type OpenAdapter = unsafe extern "C" fn(*const c_char) -> *mut Adapter;
type CloseAdapter = unsafe extern "C" fn(*mut Adapter);
type AllocatePacket = unsafe extern "C" fn() -> *mut Packet;
type InitPacket = unsafe extern "C" fn(*mut Packet, *mut c_void, u32);
type FreePacket = unsafe extern "C" fn(*mut Packet);
type SendPacket = unsafe extern "C" fn(*mut Adapter, *mut Packet, c_uchar) -> c_uchar;
type ReceivePacket = unsafe extern "C" fn(*mut Adapter, *mut Packet, c_uchar) -> c_uchar;
type SetReadTimeout = unsafe extern "C" fn(*mut Adapter, c_int) -> c_uchar;
type SetMinToCopy = unsafe extern "C" fn(*mut Adapter, c_int) -> c_uchar;
type SetBpf = unsafe extern "C" fn(*mut Adapter, *mut BpfProgram) -> c_uchar;
type GetReadEvent = unsafe extern "C" fn(*mut Adapter) -> HANDLE;

struct Api {
    module: HMODULE,
    get_adapter_names: GetAdapterNames,
    get_version: GetVersion,
    open_adapter: OpenAdapter,
    close_adapter: CloseAdapter,
    allocate_packet: AllocatePacket,
    init_packet: InitPacket,
    free_packet: FreePacket,
    send_packet: SendPacket,
    receive_packet: ReceivePacket,
    set_read_timeout: SetReadTimeout,
    set_min_to_copy: SetMinToCopy,
    set_bpf: Option<SetBpf>,
    get_read_event: GetReadEvent,
}

impl Api {
    fn load() -> Result<Self, String> {
        let dll = system_directory()?.join("Npcap").join("Packet.dll");
        if !dll.is_file() {
            return Err(format!(
                "Npcap is not installed: {} is missing. Download and install Npcap from https://npcap.com/.",
                dll.display()
            ));
        }
        let wide = dll
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: wide is a valid NUL-terminated path. Loading the exact System32 path prevents DLL
        // search-order hijacking and restricts dependencies to safe system locations.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(format!(
                "Could not load the installed Npcap Packet.dll: {}",
                std::io::Error::last_os_error()
            ));
        }
        let result = (|| {
            Ok(Self {
                module,
                // SAFETY: each symbol has the public Npcap Packet32.h ABI declared above.
                get_adapter_names: unsafe { symbol(module, b"PacketGetAdapterNames\0")? },
                // SAFETY: see above.
                get_version: unsafe { symbol(module, b"PacketGetVersion\0")? },
                // SAFETY: see above.
                open_adapter: unsafe { symbol(module, b"PacketOpenAdapter\0")? },
                // SAFETY: see above.
                close_adapter: unsafe { symbol(module, b"PacketCloseAdapter\0")? },
                // SAFETY: see above.
                allocate_packet: unsafe { symbol(module, b"PacketAllocatePacket\0")? },
                // SAFETY: see above.
                init_packet: unsafe { symbol(module, b"PacketInitPacket\0")? },
                // SAFETY: see above.
                free_packet: unsafe { symbol(module, b"PacketFreePacket\0")? },
                // SAFETY: see above.
                send_packet: unsafe { symbol(module, b"PacketSendPacket\0")? },
                // SAFETY: see above.
                receive_packet: unsafe { symbol(module, b"PacketReceivePacket\0")? },
                // SAFETY: see above.
                set_read_timeout: unsafe { symbol(module, b"PacketSetReadTimeout\0")? },
                // SAFETY: see above.
                set_min_to_copy: unsafe { symbol(module, b"PacketSetMinToCopy\0")? },
                // Optional: older Packet.dll builds may omit it, in which case capture
                // stays unfiltered and frames are filtered in user space as before.
                // SAFETY: see above.
                set_bpf: unsafe { symbol(module, b"PacketSetBpf\0").ok() },
                // SAFETY: see above.
                get_read_event: unsafe { symbol(module, b"PacketGetReadEvent\0")? },
            })
        })();
        if result.is_err() {
            // SAFETY: module was returned by LoadLibraryExW and has not been released.
            unsafe { FreeLibrary(module) };
        }
        result
    }

    fn version(&self) -> Result<String, String> {
        // SAFETY: PacketGetVersion returns a library-owned, NUL-terminated string.
        let version = unsafe { (self.get_version)() };
        if version.is_null() {
            return Err("Npcap PacketGetVersion returned a null pointer.".into());
        }
        // SAFETY: the non-null pointer follows PacketGetVersion's documented contract.
        normalize_version(
            unsafe { CStr::from_ptr(version) }
                .to_string_lossy()
                .as_ref(),
        )
    }

    fn device_names(&self) -> Result<Vec<String>, String> {
        let mut size = 0_u32;
        // Npcap returns FALSE with ERROR_INSUFFICIENT_BUFFER for this successful size query.
        // SAFETY: a null first buffer is the documented size query for PacketGetAdapterNames.
        let probe_result = unsafe { (self.get_adapter_names)(null_mut(), &mut size) };
        let mut buffer = vec![0_i8; adapter_buffer_size(probe_result, size)?];
        // SAFETY: buffer is writable for the in/out size supplied to PacketGetAdapterNames.
        if unsafe { (self.get_adapter_names)(buffer.as_mut_ptr(), &mut size) } == 0 {
            return Err("Npcap failed while reading its adapter list.".into());
        }
        let names = parse_multistring(&buffer)?
            .into_iter()
            .filter(|name| is_npcap_name(name))
            .collect::<Vec<_>>();
        if names.is_empty() {
            return Err(
                "Npcap did not report any physical NPF adapters. Verify that the Npcap service is running and bound to the selected Ethernet adapter."
                    .into(),
            );
        }
        Ok(names)
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        // SAFETY: module was loaded by LoadLibraryExW and remains owned by this Api.
        unsafe { FreeLibrary(self.module) };
    }
}

struct AdapterHandle {
    handle: *mut Adapter,
    close: CloseAdapter,
}

impl Drop for AdapterHandle {
    fn drop(&mut self) {
        // SAFETY: handle was returned by PacketOpenAdapter and is closed exactly once.
        unsafe { (self.close)(self.handle) };
    }
}

struct PacketHandle {
    packet: *mut Packet,
    free: FreePacket,
}

impl Drop for PacketHandle {
    fn drop(&mut self) {
        // SAFETY: packet was returned by PacketAllocatePacket and is freed exactly once.
        unsafe { (self.free)(self.packet) };
    }
}

pub fn available() -> bool {
    Api::load().and_then(|api| api.device_names()).is_ok()
}

pub fn version() -> Option<String> {
    Api::load().and_then(|api| api.version()).ok()
}

pub fn interface_available(interface: &str) -> bool {
    Api::load()
        .and_then(|api| find_device(&api, interface))
        .is_ok()
}

pub fn capture(interface: &str, request: &[u8], wait: Duration) -> Result<Vec<Vec<u8>>, String> {
    let api = Api::load()?;
    let device = CString::new(find_device(&api, interface)?)
        .map_err(|_| "Npcap returned an invalid adapter name.".to_string())?;
    // SAFETY: device is NUL-terminated and remains alive throughout the call.
    let adapter = unsafe { (api.open_adapter)(device.as_ptr()) };
    if adapter.is_null() {
        return Err(format!(
            "Npcap could not open interface {interface}. Run OTserver Otter as Administrator and verify that Npcap is bound to that adapter."
        ));
    }
    let adapter = AdapterHandle {
        handle: adapter,
        close: api.close_adapter,
    };
    // Immediate reads are issued only after Npcap's read event is signalled. This avoids treating
    // an ordinary quiet-network timeout as a failed capture and keeps the overall wait bounded.
    // SAFETY: adapter is open and both calls only configure this handle.
    unsafe { SetLastError(0) };
    if unsafe { (api.set_read_timeout)(adapter.handle, -1) } == 0 {
        return Err(npcap_error(
            &format!("Npcap could not configure immediate reads on interface {interface}"),
            // SAFETY: read immediately after the failed Win32 API call.
            unsafe { GetLastError() },
        ));
    }
    // SAFETY: adapter is open and the call only configures this handle.
    unsafe { SetLastError(0) };
    if unsafe { (api.set_min_to_copy)(adapter.handle, 1) } == 0 {
        return Err(npcap_error(
            &format!("Npcap could not configure capture latency on interface {interface}"),
            // SAFETY: read immediately after the failed Win32 API call.
            unsafe { GetLastError() },
        ));
    }
    // SAFETY: adapter is open; Npcap owns the returned event for the lifetime of the adapter.
    let read_event = unsafe { (api.get_read_event)(adapter.handle) };
    if read_event.is_null() {
        return Err(npcap_error(
            &format!("Npcap did not provide a capture event for interface {interface}"),
            // SAFETY: read immediately after the failed Win32 API call.
            unsafe { GetLastError() },
        ));
    }
    // Best effort: restrict the driver to PROFINET frames so a busy segment does not
    // flood the capture path. If the filter cannot be installed, capture stays
    // unfiltered and frames are filtered in user space as before.
    if let Some(set_bpf) = api.set_bpf {
        let mut instructions = DCP_FILTER;
        let mut program = BpfProgram {
            length: instructions.len() as u32,
            instructions: instructions.as_mut_ptr(),
        };
        // SAFETY: adapter is open; program and instructions outlive the call, and the
        // driver copies the filter rather than retaining the pointer.
        unsafe { (set_bpf)(adapter.handle, &mut program) };
    }
    let tx_packet = allocate_packet(&api)?;
    let rx_packet = allocate_packet(&api)?;
    let request_length = u32::try_from(request.len()).map_err(|_| "DCP request is too large.")?;
    let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_SIZE];
    let receive_length = u32::try_from(receive_buffer.len()).expect("bounded receive buffer");

    // Send one Identify-All request. Its standards-compliant response delay factor spreads
    // replies across the capture window; repeating it would multiply traffic on a busy OT cell.
    // SAFETY: Npcap does not mutate or retain the caller-owned buffer, which outlives the
    // synchronous PacketSendPacket call.
    unsafe {
        (api.init_packet)(
            tx_packet.packet,
            request.as_ptr().cast_mut().cast(),
            request_length,
        )
    };
    // SAFETY: adapter and packet remain valid; synchronous send completes before returning.
    if unsafe { (api.send_packet)(adapter.handle, tx_packet.packet, 1) } == 0 {
        return Err(format!(
            "Npcap could not transmit DCP Identify on {interface}."
        ));
    }

    let started = Instant::now();
    let mut frames = Vec::new();
    while started.elapsed() < wait {
        let remaining = wait.saturating_sub(started.elapsed());
        // SAFETY: read_event belongs to the still-open adapter and remains valid for this call.
        let wait_result = unsafe { WaitForSingleObject(read_event, wait_millis(remaining)) };
        match wait_result {
            WAIT_TIMEOUT => break,
            WAIT_OBJECT_0 => {}
            WAIT_FAILED => {
                return Err(npcap_error(
                    &format!("Npcap capture wait failed on interface {interface}"),
                    // SAFETY: read immediately after the failed Win32 API call.
                    unsafe { GetLastError() },
                ));
            }
            other => {
                return Err(format!(
                    "Npcap returned unexpected capture wait status 0x{other:08X} on interface {interface}."
                ));
            }
        }
        // SAFETY: packet is allocated by Packet.dll and buffer is writable for receive_length.
        unsafe {
            (api.init_packet)(
                rx_packet.packet,
                receive_buffer.as_mut_ptr().cast(),
                receive_length,
            )
        };
        // SAFETY: adapter and packet remain valid; the signalled event makes this immediate read
        // non-blocking while the synchronous call fills the caller-owned buffer.
        unsafe { SetLastError(0) };
        if unsafe { (api.receive_packet)(adapter.handle, rx_packet.packet, 1) } == 0 {
            return Err(npcap_error(
                &format!("Npcap capture read failed on interface {interface}"),
                // SAFETY: read immediately after the failed Win32 API call.
                unsafe { GetLastError() },
            ));
        }
        // SAFETY: rx_packet points to the public PACKET layout initialized by Packet.dll.
        let valid = unsafe { (*rx_packet.packet).bytes_received as usize };
        if valid > receive_buffer.len() {
            return Err("Npcap returned an oversized capture buffer.".into());
        }
        parse_bpf_records(&receive_buffer[..valid], &mut frames)?;
        if frames.len() > MAX_CAPTURED_FRAMES {
            return Err("Npcap capture exceeded the bounded packet limit.".into());
        }
    }
    Ok(frames)
}

fn allocate_packet(api: &Api) -> Result<PacketHandle, String> {
    // SAFETY: PacketAllocatePacket takes no arguments and returns an owned Packet.dll allocation.
    let packet = unsafe { (api.allocate_packet)() };
    if packet.is_null() {
        return Err("Npcap could not allocate a packet descriptor.".into());
    }
    Ok(PacketHandle {
        packet,
        free: api.free_packet,
    })
}

fn find_device(api: &Api, interface: &str) -> Result<String, String> {
    let expected = canonical_adapter_name(interface);
    let names = api.device_names()?;
    names
        .iter()
        .find(|name| canonical_adapter_name(name) == expected)
        .cloned()
        .ok_or_else(|| {
            format!(
                "Npcap is installed, but interface {interface} is not bound to it. Disable any obsolete Windows Network Bridge and verify the Npcap binding on the selected physical Ethernet adapter. Driver-visible adapters: {}",
                if names.is_empty() {
                    "none".into()
                } else {
                    names.join(", ")
                }
            )
        })
}

fn canonical_adapter_name(value: &str) -> String {
    value
        .trim()
        .strip_prefix(r"\Device\NPF_")
        .unwrap_or(value.trim())
        .trim_matches(['{', '}'])
        .to_ascii_uppercase()
}

fn is_npcap_name(value: &str) -> bool {
    let trimmed = value.trim();
    let Some(guid) = trimmed.strip_prefix(r"\Device\NPF_") else {
        return false;
    };
    let canonical = canonical_adapter_name(trimmed);
    guid.starts_with('{')
        && guid.ends_with('}')
        && canonical.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| canonical.as_bytes().get(index) == Some(&b'-'))
        && canonical
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn adapter_buffer_size(_: c_uchar, size: u32) -> Result<usize, String> {
    if size == 0 {
        return Err(
            "Npcap could not enumerate adapters. Verify that the Npcap service is running.".into(),
        );
    }
    Ok(size as usize)
}

fn parse_multistring(buffer: &[i8]) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut offset = 0;
    while offset < buffer.len() && buffer[offset] != 0 {
        let Some(relative_end) = buffer[offset..].iter().position(|byte| *byte == 0) else {
            return Err("Npcap returned a malformed adapter list.".into());
        };
        // SAFETY: relative_end locates a terminating NUL within buffer.
        names.push(
            unsafe { CStr::from_ptr(buffer[offset..].as_ptr()) }
                .to_string_lossy()
                .into_owned(),
        );
        offset += relative_end + 1;
    }
    Ok(names)
}

fn parse_bpf_records(buffer: &[u8], frames: &mut Vec<Vec<u8>>) -> Result<(), String> {
    let mut offset = 0;
    while offset < buffer.len() {
        if buffer.len() - offset < BPF_HEADER_MINIMUM {
            return Err("Npcap returned a truncated BPF packet header.".into());
        }
        let caplen = u32::from_ne_bytes(
            buffer[offset + 8..offset + 12]
                .try_into()
                .expect("four-byte BPF caplen"),
        ) as usize;
        let datalen = u32::from_ne_bytes(
            buffer[offset + 12..offset + 16]
                .try_into()
                .expect("four-byte BPF datalen"),
        ) as usize;
        let header_length = u16::from_ne_bytes(
            buffer[offset + 16..offset + 18]
                .try_into()
                .expect("two-byte BPF header length"),
        ) as usize;
        if header_length < BPF_HEADER_MINIMUM || caplen > datalen {
            return Err("Npcap returned an invalid BPF packet header.".into());
        }
        let data_start = offset
            .checked_add(header_length)
            .ok_or_else(|| "Npcap BPF packet offset overflowed.".to_string())?;
        let data_end = data_start
            .checked_add(caplen)
            .filter(|end| *end <= buffer.len())
            .ok_or_else(|| "Npcap returned a truncated BPF packet.".to_string())?;
        let frame = &buffer[data_start..data_end];
        if frame.len() >= 14 && frame[12..14] == [0x88, 0x92] {
            frames.push(frame.to_vec());
        }
        let record_length = align_packet(header_length + caplen);
        if record_length == 0 || offset + record_length > buffer.len() {
            return Err("Npcap returned an invalid aligned BPF packet size.".into());
        }
        offset += record_length;
    }
    Ok(())
}

fn align_packet(length: usize) -> usize {
    (length + PACKET_ALIGNMENT - 1) & !(PACKET_ALIGNMENT - 1)
}

fn wait_millis(duration: Duration) -> u32 {
    duration.as_millis().clamp(1, (u32::MAX - 1) as u128) as u32
}

fn normalize_version(version: &str) -> Result<String, String> {
    let version = version.trim();
    if version.is_empty() {
        Err("Npcap PacketGetVersion returned an empty version.".into())
    } else {
        Ok(version.to_string())
    }
}

fn npcap_error(context: &str, error: u32) -> String {
    if error == 0 {
        format!("{context}; Npcap did not provide a Windows error code.")
    } else {
        format!(
            "{context}: {}",
            std::io::Error::from_raw_os_error(error as i32)
        )
    }
}

fn system_directory() -> Result<PathBuf, String> {
    let mut buffer = [0_u16; 32_768];
    // SAFETY: buffer is writable for the supplied element count.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(format!(
            "Could not locate the Windows system directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..length])))
}

unsafe fn symbol<T: Copy>(module: HMODULE, name: &'static [u8]) -> Result<T, String> {
    // SAFETY: module is loaded and name is a NUL-terminated static symbol name.
    let address = unsafe { GetProcAddress(module, name.as_ptr()) }
        .ok_or_else(|| format!("The installed Packet.dll is missing {}.", symbol_name(name)))?;
    debug_assert_eq!(std::mem::size_of::<T>(), std::mem::size_of_val(&address));
    // SAFETY: the caller selects T corresponding to the named public Packet32 function.
    Ok(unsafe { std::mem::transmute_copy(&address) })
}

fn symbol_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        adapter_buffer_size, canonical_adapter_name, is_npcap_name, normalize_version,
        parse_bpf_records, wait_millis,
    };
    use std::time::Duration;

    #[test]
    fn canonicalizes_npf_and_windows_adapter_names() {
        assert_eq!(
            canonical_adapter_name(r"\Device\NPF_{8d11417d-4d16-4d5b-9917-c30cf60df212}"),
            "8D11417D-4D16-4D5B-9917-C30CF60DF212"
        );
        assert_eq!(
            canonical_adapter_name("{8D11417D-4D16-4D5B-9917-C30CF60DF212}"),
            "8D11417D-4D16-4D5B-9917-C30CF60DF212"
        );
        assert!(is_npcap_name(
            r"\Device\NPF_{8D11417D-4D16-4D5B-9917-C30CF60DF212}"
        ));
        assert!(!is_npcap_name("{8D11417D-4D16-4D5B-9917-C30CF60DF212}"));
    }

    #[test]
    fn accepts_npcap_failed_adapter_size_probe() {
        assert_eq!(adapter_buffer_size(0, 4096).unwrap(), 4096);
    }

    #[test]
    fn normalizes_runtime_version_and_rejects_empty_values() {
        assert_eq!(normalize_version(" 1.88 \r\n").unwrap(), "1.88");
        assert!(normalize_version("  ").is_err());
    }

    #[test]
    fn capture_wait_is_bounded_and_never_becomes_immediate() {
        assert_eq!(wait_millis(Duration::ZERO), 1);
        assert_eq!(wait_millis(Duration::from_millis(250)), 250);
        assert_eq!(wait_millis(Duration::MAX), u32::MAX - 1);
    }

    #[test]
    fn parses_bpf_records_and_keeps_only_profinet() {
        let mut record = vec![0_u8; 36];
        record[8..12].copy_from_slice(&14_u32.to_ne_bytes());
        record[12..16].copy_from_slice(&14_u32.to_ne_bytes());
        record[16..18].copy_from_slice(&20_u16.to_ne_bytes());
        record[32..34].copy_from_slice(&[0x88, 0x92]);
        let mut frames = Vec::new();
        parse_bpf_records(&record, &mut frames).unwrap();
        assert_eq!(frames.len(), 1);

        record[32..34].copy_from_slice(&[0x08, 0x00]);
        frames.clear();
        parse_bpf_records(&record, &mut frames).unwrap();
        assert!(frames.is_empty());
    }

    fn run_filter(filter: &[super::BpfInsn], frame: &[u8]) -> u32 {
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;
        loop {
            let insn = &filter[pc];
            match insn.code {
                0x28 => {
                    let offset = insn.k as usize;
                    accumulator = u16::from_be_bytes([frame[offset], frame[offset + 1]]) as u32;
                    pc += 1;
                }
                0x15 => {
                    pc += 1 + if accumulator == insn.k {
                        insn.jt
                    } else {
                        insn.jf
                    } as usize;
                }
                0x06 => return insn.k,
                code => panic!("unexpected BPF opcode {code:#04x}"),
            }
        }
    }

    #[test]
    fn dcp_filter_accepts_only_profinet_ethertype() {
        let mut profinet = vec![0_u8; 60];
        profinet[12..14].copy_from_slice(&[0x88, 0x92]);
        assert!(run_filter(&super::DCP_FILTER, &profinet) > 0);

        let mut ipv4 = vec![0_u8; 60];
        ipv4[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(run_filter(&super::DCP_FILTER, &ipv4), 0);
    }
}
