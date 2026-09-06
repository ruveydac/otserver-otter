//! Process-wide discovery pacing, not an on-wire packet shaper.
//! The supplied site ceilings are 50 ARP requests/s and 500 packets/s, not universal OT limits.

use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const ARP_REQUESTS_PER_SECOND: u64 = 50 * 70 / 100;
pub const OPERATIONS_PER_SECOND: u64 = 500 * 70 / 100;
const ARP_INTERVAL: Duration =
    Duration::from_nanos(1_000_000_000_u64.div_ceil(ARP_REQUESTS_PER_SECOND));
const INTERVAL: Duration = Duration::from_nanos(1_000_000_000_u64.div_ceil(OPERATIONS_PER_SECOND));

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Arp,
    Other,
}

#[derive(Default)]
struct Budget {
    next: Option<Instant>,
    next_arp: Option<Instant>,
}

impl Budget {
    fn take(&mut self, now: Instant, kind: Kind) -> Duration {
        let mut next = self.next.unwrap_or(now);
        if kind == Kind::Arp {
            next = next.max(self.next_arp.unwrap_or(now));
        }
        let delay = next.saturating_duration_since(now);
        if delay.is_zero() {
            self.sent(now, kind);
        }
        delay
    }

    fn sent(&mut self, now: Instant, kind: Kind) {
        // Advance from actual activity, never from overdue slots: idle time earns no burst.
        self.next = Some(now + INTERVAL);
        if kind == Kind::Arp {
            self.next_arp = Some(now + ARP_INTERVAL);
        }
    }
}

static BUDGET: Mutex<Budget> = Mutex::new(Budget {
    next: None,
    next_arp: None,
});
static BLOCKING_SEND: Mutex<()> = Mutex::new(());

fn delay(kind: Kind) -> Duration {
    BUDGET
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take(Instant::now(), kind)
}

pub(crate) fn send_blocking<T>(kind: Kind, send: impl FnOnce() -> T) -> T {
    // Serialize the actual raw/API sends, not just permission to send. A descheduled sender
    // must not bunch its ARP frame together with the next sender when it resumes.
    let _sending = BLOCKING_SEND
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    loop {
        let delay = delay(kind);
        if delay.is_zero() {
            break;
        }
        std::thread::sleep(delay);
    }
    let result = send();
    BUDGET
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .sent(Instant::now(), kind);
    result
}

pub(crate) async fn wait() {
    wait_for(Kind::Other).await;
}

async fn wait_for(kind: Kind) {
    loop {
        let delay = delay(kind);
        if delay.is_zero() {
            return;
        }
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_keep_thirty_percent_headroom_without_bursts() {
        assert_eq!(ARP_REQUESTS_PER_SECOND, 35);
        assert_eq!(OPERATIONS_PER_SECOND, 350);
        for (kind, rate, interval) in [
            (Kind::Arp, ARP_REQUESTS_PER_SECOND, ARP_INTERVAL),
            (Kind::Other, OPERATIONS_PER_SECOND, INTERVAL),
        ] {
            let mut budget = Budget::default();
            let start = Instant::now();
            for index in 0..=rate {
                let now = start + interval * index as u32;
                assert!(budget.take(now, kind).is_zero());
                assert_eq!(budget.take(now, kind), interval);
                assert!(
                    !budget
                        .take(now + interval - Duration::from_nanos(1), kind)
                        .is_zero()
                );
            }
            assert!(interval * rate as u32 >= Duration::from_secs(1));
            let late = start + Duration::from_secs(60);
            assert!(budget.take(late, kind).is_zero());
            assert_eq!(budget.take(late, kind), interval);
        }
        let mut budget = Budget::default();
        let now = Instant::now();
        assert!(budget.take(now, Kind::Arp).is_zero());
        assert_eq!(budget.take(now, Kind::Other), INTERVAL);
        assert!(budget.take(now + INTERVAL, Kind::Other).is_zero());
        assert_eq!(
            budget.take(now + INTERVAL, Kind::Arp),
            ARP_INTERVAL - INTERVAL
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_raw_senders_share_the_arp_budget() {
        let times = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    send_blocking(Kind::Arp, || {
                        // Simulate a send which stalls after obtaining permission.
                        std::thread::sleep(Duration::from_millis(5));
                        times.lock().unwrap().push(Instant::now());
                    });
                });
            }
        });
        let times = times.into_inner().unwrap();
        assert!(
            times
                .windows(2)
                .all(|pair| pair[1] - pair[0] >= ARP_INTERVAL)
        );
        wait().await;
        assert!(times.last().unwrap().elapsed() >= INTERVAL);
    }
}
