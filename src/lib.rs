use serde::{Deserialize, Serialize};

pub mod contract;
pub mod discovery;
pub mod profinet;
pub mod protocols;
pub mod snmp;
pub mod traffic;

pub const VERSION: &str = env!("OTTER_BUILD_VERSION");

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    Single(T),
    Multiple(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::Single(value) => vec![value.clone()],
            Self::Multiple(values) => values.clone(),
        }
    }
}

#[cfg(test)]
pub(crate) async fn network_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

pub fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting is infallible")
}
