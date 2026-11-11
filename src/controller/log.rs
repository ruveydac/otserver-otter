use super::{Error, store};
use crate::LogOutput;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
// shortcut: log retention is operator-managed; add rotation if unattended log volume requires it.
pub(super) struct Log(Option<Arc<Mutex<File>>>);

impl Log {
    pub(super) fn open(directory: Option<&Path>) -> Result<Self, Error> {
        directory
            .map(store::open_log)
            .transpose()
            .map(|file| Self(file.map(|file| Arc::new(Mutex::new(file)))))
    }

    pub(super) fn warn(&self, message: &str) {
        self.write("WARN", message);
    }

    pub(super) fn error(&self, message: &str) {
        self.write("ERROR", message);
    }

    fn write(&self, level: &str, message: &str) {
        let Some(file) = &self.0 else { return };
        let message: String = message
            .chars()
            .take(2048)
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect();
        let result = file.lock().map_err(|_| ()).and_then(|mut file| {
            writeln!(file, "{} {level} {message}", otserver_otter::now())
                .and_then(|()| file.flush())
                .map_err(|_| ())
        });
        if result.is_err() {
            eprintln!(
                "Could not append to controller.log in the state directory. Check disk space and file permissions."
            );
        }
    }
}

pub(super) struct ScanLog<'a> {
    pub(super) log: &'a Log,
    pub(super) run_id: &'a str,
}

impl LogOutput for ScanLog<'_> {
    fn write(&self, _message: String) {}

    fn diagnostic(&self, protocol: &str, status: &str, code: &str) {
        if !matches!(status, "FAIL" | "PARTIAL" | "CANCELLED") {
            return;
        }
        // Only caller-owned categories reach disk; arbitrary protocol error text can contain secrets.
        let hint = crate::diagnostic_hint(code).unwrap_or(match code {
            "source-mac-refreshed" => {
                "The configured source MAC was stale; discovery uses the adapter's current MAC."
            }
            "probe-task-failed" => "A discovery task failed; other collected results are retained.",
            _ => "Discovery was incomplete; review the retained scan export for affected targets.",
        });
        let message = format!(
            "Run {}: {protocol} {status} code={code}. {hint}",
            self.run_id
        );
        if status == "FAIL" {
            self.log.error(&message);
        } else {
            self.log.warn(&message);
        }
    }
}
