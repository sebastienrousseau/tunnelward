// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! [`Sink`]: takes entries from request tasks without blocking them and
//! writes them, chained and checkpointed, from a thread of its own.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;
use tunnelward_crypto::composite::SigningKey;

use crate::{Entry, Pseudonyms, Raw, chain, raw, receipt};

/// Longest last line [`Sink::open`] reads back to continue a file.
const MAX_TAIL: u64 = 1 << 20;
/// How often the raw file is pruned.
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// A day, in milliseconds.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// The longest raw window D7 allows, in days.
pub const MAX_RAW_DAYS: u32 = 30;

/// How a [`Sink`] writes.
#[derive(Debug)]
#[non_exhaustive]
pub struct Settings {
    /// The log file, created if absent, continued if not.
    pub path: PathBuf,
    /// Signs checkpoints, and receipts when they are on.
    pub key: SigningKey,
    /// The key for pseudonyms.
    pub pseudonym_key: [u8; crate::PSEUDONYM_KEY_LEN],
    /// A checkpoint after this many lines (1,000 by default).
    pub checkpoint_every: u64,
    /// A checkpoint after this long with unsigned lines (60 s).
    pub checkpoint_interval: Duration,
    /// Days to keep raw addresses beside the log; 0 (the default) keeps
    /// none. At most [`MAX_RAW_DAYS`].
    pub raw_days: u32,
    /// Whether answers carry a signed receipt.
    pub receipts: bool,
    /// Entries waiting to be written before more are dropped (16,384).
    pub queue: usize,
}

impl Settings {
    /// Defaults for the log at `path`.
    #[must_use]
    pub fn new(path: PathBuf, key: SigningKey, pseudonym_key: [u8; 32]) -> Self {
        Self {
            path,
            key,
            pseudonym_key,
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(60),
            raw_days: 0,
            receipts: false,
            queue: 16_384,
        }
    }
}

enum Message {
    Entry(Box<Entry>, u64, Option<Raw>),
    Stop,
}

/// An open audit log.
pub struct Sink {
    tx: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
    pseudonyms: Pseudonyms,
    key: Arc<SigningKey>,
    key_id: String,
    raw: bool,
    receipts: bool,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl core::fmt::Debug for Sink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sink")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Sink {
    /// Opens the log in `settings` and starts its writer.
    ///
    /// # Errors
    ///
    /// The file cannot be opened or read, its last line is incomplete or
    /// is not a log line, or `raw_days` is over [`MAX_RAW_DAYS`].
    pub fn open(settings: Settings) -> Result<Self, String> {
        if settings.raw_days > MAX_RAW_DAYS {
            return Err(format!("raw_days is at most {MAX_RAW_DAYS}"));
        }
        let shown = settings.path.display().to_string();
        let (next, prev) = tail(&settings.path).map_err(|e| format!("{shown}: {e}"))?;
        let file = append(&settings.path).map_err(|e| format!("{shown}: {e}"))?;
        let key = Arc::new(settings.key);
        let key_id = chain::key_id(&key.public_key());
        let (tx, rx) = std::sync::mpsc::sync_channel(settings.queue.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let writer = Writer {
            file: BufWriter::new(file),
            raw: (settings.raw_days > 0).then(|| raw::path(&settings.path)),
            raw_days: settings.raw_days,
            next,
            prev,
            key: key.clone(),
            key_id: key_id.clone(),
            unsigned: 0,
            every: settings.checkpoint_every.max(1),
            interval: settings.checkpoint_interval,
            last_checkpoint: Instant::now(),
            last_prune: None,
            dropped: dropped.clone(),
        };
        let handle = std::thread::Builder::new()
            .name("tunnelward-audit".into())
            .spawn(move || writer.run(&rx))
            .map_err(|e| format!("audit writer: {e}"))?;
        Ok(Self {
            tx,
            dropped,
            pseudonyms: Pseudonyms::new(&settings.pseudonym_key),
            key,
            key_id,
            raw: settings.raw_days > 0,
            receipts: settings.receipts,
            writer: Mutex::new(Some(handle)),
        })
    }

    /// Queues `entry`, with the raw values behind its pseudonyms when the
    /// log keeps them. Never blocks: when the queue is full the entry is
    /// dropped, and the log records a gap with the count.
    pub fn record(&self, entry: Entry, raw: Option<Raw>) {
        let raw = raw.filter(|_| self.raw);
        let message = Message::Entry(Box::new(entry), crate::now_ms(), raw);
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.tx.try_send(message)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The pseudonyms this log writes.
    #[must_use]
    pub fn pseudonyms(&self) -> &Pseudonyms {
        &self.pseudonyms
    }

    /// Whether raw values are kept beside the log.
    #[must_use]
    pub fn keeps_raw(&self) -> bool {
        self.raw
    }

    /// The receipt for `body`, signed, when receipts are on.
    #[must_use]
    pub fn receipt(&self, body: &receipt::Receipt) -> Option<String> {
        if !self.receipts {
            return None;
        }
        receipt::issue(&self.key, &self.key_id, body).ok()
    }

    /// The public key that verifies checkpoints and receipts.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    /// Writes a last checkpoint and stops the writer. Entries recorded
    /// after this are dropped and counted.
    pub fn close(&self) {
        let handle = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            let _sent = self.tx.send(Message::Stop);
            let _joined = handle.join();
        }
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.close();
    }
}

/// The file at `path` opened to append, owner-only when created.
fn append(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn invalid(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what)
}

/// The last [`MAX_TAIL`] bytes of the file at `path`, and whether they
/// are all of it; `None` when there is no file.
fn last_bytes(path: &Path) -> std::io::Result<Option<(Vec<u8>, bool)>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let start = file.metadata()?.len().saturating_sub(MAX_TAIL);
    file.seek(SeekFrom::Start(start))?;
    let mut text = Vec::new();
    file.read_to_end(&mut text)?;
    Ok(Some((text, start == 0)))
}

/// The last complete line of `text`; `None` when `text` is empty.
fn last_line(text: &[u8], whole: bool) -> std::io::Result<Option<&[u8]>> {
    if text.is_empty() {
        return Ok(None);
    }
    let body = text
        .strip_suffix(b"\n")
        .ok_or_else(|| invalid("the last line is incomplete; repair the file by hand"))?;
    match body.iter().rposition(|&b| b == b'\n') {
        Some(at) => Ok(Some(&body[at + 1..])),
        None if whole => Ok(Some(body)),
        None => Err(invalid("the last line is over 1 MiB")),
    }
}

/// Where to continue the log at `path`: the next `seq`, and the hash of
/// the last line. A new or empty file starts at 0 and [`chain::GENESIS`].
fn tail(path: &Path) -> std::io::Result<(u64, String)> {
    let start = || (0, chain::GENESIS.to_owned());
    let Some((text, whole)) = last_bytes(path)? else {
        return Ok(start());
    };
    let Some(line) = last_line(&text, whole)? else {
        return Ok(start());
    };
    let seq = serde_json::from_slice::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("seq")?.as_u64())
        .ok_or_else(|| invalid("the last line is not an audit line"))?;
    Ok((seq + 1, chain::hash_line(line)))
}

/// A line: the chain fields, then the body's own.
#[derive(Serialize)]
struct Line<'a, T: Serialize> {
    seq: u64,
    prev: &'a str,
    time: u64,
    #[serde(flatten)]
    body: &'a T,
}

/// The lines the writer adds on its own.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Mark<'a> {
    Checkpoint { key: &'a str, sig: String },
    Gap { dropped: u64 },
}

struct Writer {
    file: BufWriter<File>,
    raw: Option<PathBuf>,
    raw_days: u32,
    next: u64,
    prev: String,
    key: Arc<SigningKey>,
    key_id: String,
    unsigned: u64,
    every: u64,
    interval: Duration,
    last_checkpoint: Instant,
    last_prune: Option<Instant>,
    dropped: Arc<AtomicU64>,
}

impl Writer {
    fn run(mut self, rx: &Receiver<Message>) {
        self.prune();
        loop {
            let wait = self.interval.saturating_sub(self.last_checkpoint.elapsed());
            let stop = match rx.recv_timeout(wait) {
                Ok(message) => self.handle(message, rx),
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => true,
            };
            self.gap();
            if stop || self.last_checkpoint.elapsed() >= self.interval {
                if self.unsigned > 0 {
                    self.checkpoint();
                }
                // With nothing to sign, the timer starts again.
                self.last_checkpoint = Instant::now();
            }
            self.flush();
            if stop {
                return;
            }
            self.prune();
        }
    }

    /// Writes `message` and any others already waiting; whether to stop.
    fn handle(&mut self, first: Message, rx: &Receiver<Message>) -> bool {
        let mut message = Some(first);
        while let Some(m) = message {
            match m {
                Message::Stop => return true,
                Message::Entry(entry, time, raw) => self.entry(&entry, time, raw.as_ref()),
            }
            if self.unsigned >= self.every {
                self.checkpoint();
            }
            message = rx.try_recv().ok();
        }
        false
    }

    fn entry(&mut self, entry: &Entry, time: u64, raw: Option<&Raw>) {
        let seq = self.next;
        if self.write(entry, time).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let (Some(path), Some(raw)) = (&self.raw, raw) {
            let _kept = raw::line(seq, time, raw)
                .map(|text| append(path).and_then(|mut f| writeln!(f, "{text}")));
        }
    }

    /// Records the entries dropped since the last gap line, if any.
    fn gap(&mut self) {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 && self.write(&Mark::Gap { dropped }, crate::now_ms()).is_err() {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
        }
    }

    fn checkpoint(&mut self) {
        let time = crate::now_ms();
        if let Ok(sig) = chain::sign(&self.key, self.next, &self.prev, time) {
            let key_id = self.key_id.clone();
            let mark = Mark::Checkpoint {
                key: &key_id,
                sig: crate::b64::encode(&sig),
            };
            if self.write(&mark, time).is_ok() {
                self.unsigned = 0;
                self.flush();
                let _synced = self.file.get_ref().sync_data();
            }
        }
        self.last_checkpoint = Instant::now();
    }

    /// Appends one line with `body`, chained to the last.
    fn write<T: Serialize>(&mut self, body: &T, time: u64) -> std::io::Result<()> {
        let line = Line {
            seq: self.next,
            prev: &self.prev,
            time,
            body,
        };
        let text = serde_json::to_vec(&line)?;
        self.file.write_all(&text)?;
        self.file.write_all(b"\n")?;
        self.prev = chain::hash_line(&text);
        self.next += 1;
        self.unsigned += 1;
        Ok(())
    }

    fn flush(&mut self) {
        let _flushed = self.file.flush();
    }

    /// Prunes the raw file to its window, at start and then daily.
    fn prune(&mut self) {
        let due = self.last_prune.is_none_or(|t| t.elapsed() >= PRUNE_EVERY);
        if let (Some(path), true) = (&self.raw, due) {
            let cutoff = crate::now_ms().saturating_sub(u64::from(self.raw_days) * DAY_MS);
            let _pruned = raw::prune(path, cutoff);
            self.last_prune = Some(Instant::now());
        }
    }
}
