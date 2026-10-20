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
    sent_at: Vec<Instant>,
    sends_at_receive: Vec<usize>,
    fail_send: bool,
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
            sent_at: Vec::new(),
            sends_at_receive: Vec::new(),
            fail_send: false,
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
        adapter.sent_at.push(Instant::now());
        if adapter.fail_send {
            return 0;
        }
        if !adapter.response.is_empty()
            && adapter.filter == CAPTURE_HW_FILTER
            && adapter.kernel_buffer >= adapter.response.len()
        {
            SetEvent(adapter.event);
        }
    }
    // Reproduce the original failure: transmitting succeeds even when capture is unconfigured.
    1
}

unsafe extern "C" fn receive(adapter: *mut Adapter, packet: *mut Packet, _: c_uchar) -> c_uchar {
    // SAFETY: PacketInitPacket provided the writable receive buffer, bounded by length.
    unsafe {
        let adapter = state(adapter);
        adapter.sends_at_receive.push(adapter.sends);
        let response = &adapter.response;
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
        std::iter::once([0; 60]),
        Duration::from_millis(100),
        &cancelled,
        CaptureFilter::Dcp,
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
        std::iter::once([0; 60]),
        Duration::from_millis(100),
        &AtomicBool::new(false),
        CaptureFilter::Dcp,
        |_| Ok(None),
    )
    .unwrap_err();
    assert!(error.contains("could not allocate capture buffer"));
    assert_eq!(adapter.sends, 0);
    assert_eq!(adapter.closes, 1);
}

#[test]
fn arp_sweep_paces_sends_without_waiting_for_each_missing_reply() {
    let mut adapter = MockAdapter::new(false);
    adapter.response.clear();
    OPEN_ADAPTER.set((&mut adapter as *mut MockAdapter).cast());
    let wait = Duration::from_secs(1);
    capture_with_api(
        &mock_api(),
        INTERFACE,
        std::iter::repeat_n([0; 42], 5),
        wait,
        &AtomicBool::new(false),
        CaptureFilter::Arp,
        |_| panic!("silent targets have no reply"),
    )
    .unwrap();
    assert_eq!(adapter.sends, 5);
    let interval =
        Duration::from_nanos(1_000_000_000_u64.div_ceil(crate::traffic::ARP_REQUESTS_PER_SECOND));
    assert!(
        adapter
            .sent_at
            .windows(2)
            .all(|pair| pair[1] - pair[0] >= interval)
    );
    assert!(
        adapter.sent_at[4] - adapter.sent_at[0] < wait,
        "the response window belongs to the whole sweep"
    );
    assert!(
        adapter.sent_at[4].elapsed() >= wait,
        "late replies need a full grace period after the final send"
    );
    assert!(adapter.sends_at_receive.is_empty());
    assert_eq!(adapter.closes, 1);
}

#[test]
fn arp_sweep_receives_between_sends_and_stops_on_cancellation() {
    use crate::discovery::{reply, request};
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::Ipv4Addr;

    let source_mac = [0, 1, 2, 3, 4, 5];
    let target_mac = [0, 17, 34, 51, 68, 85];
    let source_ip = Ipv4Addr::new(192, 0, 2, 10);
    let targets = [
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        Ipv4Addr::new(192, 0, 2, 3),
    ];
    let mut adapter = MockAdapter::new(false);
    // An unsolicited reply for target 2 arrives alongside target 1's reply on the first read.
    for ip in targets[..2].iter().rev() {
        let mut frame = request(source_mac, source_ip, *ip);
        frame[..6].copy_from_slice(&source_mac);
        frame[6..12].copy_from_slice(&target_mac);
        frame[20..22].copy_from_slice(&[0, 2]);
        frame[22..28].copy_from_slice(&target_mac);
        frame[28..32].copy_from_slice(&ip.octets());
        frame[32..38].copy_from_slice(&source_mac);
        frame[38..42].copy_from_slice(&source_ip.octets());
        adapter.response.extend(super::tests::bpf_record(&frame));
    }
    OPEN_ADAPTER.set((&mut adapter as *mut MockAdapter).cast());
    let requested = RefCell::new(BTreeSet::new());
    let cancelled = AtomicBool::new(false);
    let mut replies = BTreeMap::new();
    let mut reads = 0;
    capture_with_api(
        &mock_api(),
        INTERFACE,
        targets.iter().map(|&ip| {
            requested.borrow_mut().insert(ip);
            request(source_mac, source_ip, ip)
        }),
        Duration::from_secs(60),
        &cancelled,
        CaptureFilter::Arp,
        |frame| {
            reads += 1;
            if let Some((ip, mac)) = reply(frame, &requested.borrow(), source_mac, source_ip) {
                replies.insert(ip, mac);
            }
            if reads == 2 {
                assert_eq!(replies, BTreeMap::from([(targets[0], target_mac)]));
            }
            if reads == 4 {
                cancelled.store(true, Ordering::Relaxed);
            }
            Ok(None)
        },
    )
    .unwrap();
    assert_eq!(
        replies,
        BTreeMap::from([(targets[0], target_mac), (targets[1], target_mac)])
    );
    assert_eq!(adapter.sends, 2);
    assert_eq!(adapter.sends_at_receive, [1, 2]);
    assert_eq!(adapter.closes, 1);
}

#[test]
fn arp_sweep_skips_empty_or_cancelled_work_and_propagates_failures() {
    let mut adapter = MockAdapter::new(false);
    OPEN_ADAPTER.set((&mut adapter as *mut MockAdapter).cast());
    for (count, cancelled) in [(0, false), (2, true)] {
        capture_with_api(
            &mock_api(),
            INTERFACE,
            std::iter::repeat_n([0; 42], count),
            Duration::ZERO,
            &AtomicBool::new(cancelled),
            CaptureFilter::Arp,
            |_| panic!("must not read"),
        )
        .unwrap();
    }
    assert_eq!(adapter.sends, 0);
    assert_eq!(adapter.closes, 0);
    adapter.fail_send = true;
    let error = capture_with_api(
        &mock_api(),
        INTERFACE,
        std::iter::repeat_n([0; 42], 2),
        Duration::ZERO,
        &AtomicBool::new(false),
        CaptureFilter::Arp,
        |_| panic!("failed send must stop capture"),
    )
    .unwrap_err();
    assert!(error.contains("could not transmit"));
    assert_eq!(adapter.sends, 1);
    assert_eq!(adapter.closes, 1);

    adapter.fail_send = false;
    adapter.response = vec![0; 2];
    let error = capture_with_api(
        &mock_api(),
        INTERFACE,
        std::iter::repeat_n([0; 42], 2),
        Duration::ZERO,
        &AtomicBool::new(false),
        CaptureFilter::Arp,
        |_| panic!("malformed BPF must not be delivered"),
    )
    .unwrap_err();
    assert!(error.contains("truncated BPF packet header"));
    assert_eq!(adapter.sends, 2);
    assert_eq!(adapter.closes, 2);
}
