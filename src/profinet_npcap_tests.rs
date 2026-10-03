//! Driver-free regression tests for Windows Packet.dll capture initialization.

use super::*;
use std::cell::Cell;
use std::mem::ManuallyDrop;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

const INTERFACE: &str = "{8D11417D-4D16-4D5B-9917-C30CF60DF212}";
const ADAPTER_NAME: &[u8] = b"\\Device\\NPF_{8D11417D-4D16-4D5B-9917-C30CF60DF212}\0\0";

thread_local! {
    static OPEN_ADAPTER: Cell<*mut Adapter> = const { Cell::new(null_mut()) };
}

struct MockAdapter {
    event: HANDLE,
    filter: u32,
    kernel_buffer: usize,
    fail_buffer_setup: bool,
    sends: usize,
    closes: usize,
    response: Vec<u8>,
}

impl MockAdapter {
    fn new(fail_buffer_setup: bool) -> Self {
        // SAFETY: unnamed, auto-reset event with no security attributes.
        let event = unsafe { CreateEventW(null_mut(), 0, 0, null_mut()) };
        assert!(!event.is_null());
        let mut frame = vec![0_u8; 60];
        frame[12..18].copy_from_slice(&[0x88, 0x92, 0xfe, 0xff, 0x05, 0x01]);
        Self {
            event,
            filter: 0,
            // PacketOpenAdapter starts with no kernel capture buffer. Sending can succeed
            // in that state, but incoming DCP replies never reach PacketReceivePacket.
            kernel_buffer: 0,
            fail_buffer_setup,
            sends: 0,
            closes: 0,
            response: super::tests::bpf_record(&frame),
        }
    }
}

impl Drop for MockAdapter {
    fn drop(&mut self) {
        OPEN_ADAPTER.set(null_mut());
        // SAFETY: this mock owns the event, and capture has already returned.
        unsafe { CloseHandle(self.event) };
    }
}

unsafe fn state<'a>(adapter: *mut Adapter) -> &'a mut MockAdapter {
    // SAFETY: tests pass their live MockAdapter to each synchronous mocked API call.
    unsafe { &mut *adapter.cast::<MockAdapter>() }
}

unsafe extern "C" fn adapter_names(buffer: *mut c_char, size: *mut u32) -> c_uchar {
    // SAFETY: capture supplies a writable size and then a buffer of the requested size.
    unsafe {
        *size = ADAPTER_NAME.len() as u32;
        if buffer.is_null() {
            return 0;
        }
        std::ptr::copy_nonoverlapping(ADAPTER_NAME.as_ptr().cast(), buffer, ADAPTER_NAME.len());
    }
    1
}

unsafe extern "C" fn version() -> *const c_char {
    c"mock".as_ptr()
}

unsafe extern "C" fn open(_: *const c_char) -> *mut Adapter {
    OPEN_ADAPTER.get()
}

unsafe extern "C" fn close(adapter: *mut Adapter) {
    // SAFETY: adapter is the live mock supplied by the test.
    unsafe { state(adapter).closes += 1 };
}

unsafe extern "C" fn allocate() -> *mut Packet {
    // SAFETY: the public Packet layout permits zero initialization before PacketInitPacket.
    Box::into_raw(Box::new(unsafe { std::mem::zeroed() }))
}

unsafe extern "C" fn init(packet: *mut Packet, buffer: *mut c_void, length: u32) {
    // SAFETY: packet is owned by capture, and buffer outlives the synchronous send/receive.
    unsafe {
        (*packet).buffer = buffer;
        (*packet).length = length;
        (*packet).bytes_received = 0;
    }
}

unsafe extern "C" fn free(packet: *mut Packet) {
    // SAFETY: each packet was allocated by allocate and is freed once by PacketHandle.
    drop(unsafe { Box::from_raw(packet) });
}

unsafe extern "C" fn send(adapter: *mut Adapter, _: *mut Packet, _: c_uchar) -> c_uchar {
    // SAFETY: adapter is the live mock; its event remains valid until the test ends.
    unsafe {
        let adapter = state(adapter);
        adapter.sends += 1;
        if adapter.filter == CAPTURE_HW_FILTER && adapter.kernel_buffer >= adapter.response.len() {
            SetEvent(adapter.event);
        }
    }
    // Reproduce the original failure: transmitting succeeds even when capture is unconfigured.
    1
}

unsafe extern "C" fn receive(adapter: *mut Adapter, packet: *mut Packet, _: c_uchar) -> c_uchar {
    // SAFETY: PacketInitPacket provided the writable receive buffer, bounded by length.
    unsafe {
        let response = &state(adapter).response;
        if response.len() > (*packet).length as usize {
            return 0;
        }
        std::ptr::copy_nonoverlapping(response.as_ptr(), (*packet).buffer.cast(), response.len());
        (*packet).bytes_received = response.len() as u32;
    }
    1
}

unsafe extern "C" fn set_integer(_: *mut Adapter, _: c_int) -> c_uchar {
    1
}

unsafe extern "C" fn set_buffer(adapter: *mut Adapter, size: c_int) -> c_uchar {
    // SAFETY: adapter is the live mock supplied by the test.
    let adapter = unsafe { state(adapter) };
    if adapter.fail_buffer_setup {
        return 0;
    }
    adapter.kernel_buffer = size.max(0) as usize;
    1
}

unsafe extern "C" fn set_filter(adapter: *mut Adapter, filter: u32) -> c_uchar {
    // SAFETY: adapter is the live mock supplied by the test.
    unsafe { state(adapter).filter = filter };
    1
}

unsafe extern "C" fn read_event(adapter: *mut Adapter) -> HANDLE {
    // SAFETY: adapter is the live mock supplied by the test.
    unsafe { state(adapter).event }
}

fn mock_api() -> ManuallyDrop<Api> {
    // No DLL is loaded: prevent Api's DLL ownership destructor from running.
    ManuallyDrop::new(Api {
        module: null_mut(),
        get_adapter_names: adapter_names,
        get_version: version,
        open_adapter: open,
        close_adapter: close,
        allocate_packet: allocate,
        init_packet: init,
        free_packet: free,
        send_packet: send,
        receive_packet: receive,
        set_read_timeout: set_integer,
        set_min_to_copy: set_integer,
        set_buff: set_buffer,
        set_hw_filter: set_filter,
        set_bpf: None,
        get_read_event: read_event,
    })
}

#[test]
fn receives_dcp_when_opened_adapter_has_no_kernel_buffer() {
    let mut adapter = MockAdapter::new(false);
    OPEN_ADAPTER.set((&mut adapter as *mut MockAdapter).cast());
    let cancelled = AtomicBool::new(false);
    let mut frames = Vec::new();
    capture_with_api(
        &mock_api(),
        INTERFACE,
        &[0; 60],
        Duration::from_millis(100),
        &cancelled,
        true,
        |frame| {
            frames.push(frame.to_vec());
            cancelled.store(true, Ordering::Relaxed);
            Ok(None)
        },
    )
    .unwrap();
    assert_eq!(
        frames.len(),
        1,
        "successful sends must also collect DCP replies"
    );
    assert_eq!(frames[0][12..18], [0x88, 0x92, 0xfe, 0xff, 0x05, 0x01]);
    assert_eq!(adapter.sends, 1);
    assert_eq!(adapter.closes, 1);
}

#[test]
fn failed_kernel_buffer_setup_stops_before_sending() {
    let mut adapter = MockAdapter::new(true);
    OPEN_ADAPTER.set((&mut adapter as *mut MockAdapter).cast());
    let error = capture_with_api(
        &mock_api(),
        INTERFACE,
        &[0; 60],
        Duration::from_millis(100),
        &AtomicBool::new(false),
        true,
        |_| Ok(None),
    )
    .unwrap_err();
    assert!(error.contains("could not allocate capture buffer"));
    assert_eq!(adapter.sends, 0);
    assert_eq!(adapter.closes, 1);
}
