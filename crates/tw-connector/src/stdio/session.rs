// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One MCP session: a child process speaking JSON-RPC over stdio, one
//! message per line. Responses go back to the request that waits for
//! them; everything else the server sends is an event, numbered and
//! kept for replay, and pushed to any open event stream.
//!
//! The process is started with `std::process`, its output read on a
//! thread of its own and its input written from tokio's blocking pool,
//! so the bridge needs no process support from tokio (which would add
//! crates to audit).

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use super::StdioConfig;

/// A numbered message the server sent on its own.
pub(crate) type Event = (u64, String);

/// Events kept for replay, and the open streams that get new ones.
#[derive(Default)]
struct Events {
    next: u64,
    log: VecDeque<Event>,
    streams: Vec<mpsc::Sender<Event>>,
}

/// One session and its child process.
pub(crate) struct Session {
    stdin: Arc<Mutex<ChildStdin>>,
    child: Mutex<Option<Child>>,
    waiters: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    events: Mutex<Events>,
    used: Mutex<Instant>,
    alive: AtomicBool,
    replay: usize,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A JSON-RPC id as a map key: its JSON text.
pub(crate) fn id_key(id: &Value) -> String {
    id.to_string()
}

impl Session {
    /// Starts the configured server and the task that reads its output.
    pub(crate) fn start(config: &StdioConfig) -> Result<std::sync::Arc<Self>, String> {
        let mut child = Command::new(&config.program)
            .args(&config.args)
            .envs(config.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", config.program))?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err("the server's stdio is not piped".into());
        };
        let session = Arc::new(Self {
            stdin: Arc::new(Mutex::new(stdin)),
            child: Mutex::new(Some(child)),
            waiters: Mutex::new(HashMap::new()),
            events: Mutex::new(Events::default()),
            used: Mutex::new(Instant::now()),
            alive: AtomicBool::new(true),
            replay: config.replay,
        });
        let reader = session.clone();
        let max = config.max_line;
        std::thread::spawn(move || read(stdout, &reader, max));
        Ok(session)
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub(crate) fn touch(&self) {
        *lock(&self.used) = Instant::now();
    }

    pub(crate) fn idle_since(&self) -> Instant {
        *lock(&self.used)
    }

    /// Waits for the response to the request with `id`.
    pub(crate) fn expect(&self, id: &Value) -> oneshot::Receiver<Value> {
        let (tx, rx) = oneshot::channel();
        lock(&self.waiters).insert(id_key(id), tx);
        rx
    }

    /// Writes one message as one line, off the async threads: a server
    /// that stops reading must not stall them.
    pub(crate) async fn send(&self, message: &Value) -> Result<(), String> {
        let mut line = message.to_string();
        line.push('\n');
        let stdin = self.stdin.clone();
        let written = tokio::task::spawn_blocking(move || {
            let mut stdin = lock(&stdin);
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.flush())
        });
        written
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("writing to the server: {e}"))
    }

    /// The kept events after `last` (all of them without one), and a
    /// stream of those still to come, taken together so none is lost.
    pub(crate) fn subscribe(&self, last: Option<u64>) -> (Vec<Event>, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel(64);
        let mut events = lock(&self.events);
        let missed = events
            .log
            .iter()
            .filter(|(n, _)| last.is_none_or(|l| *n > l))
            .cloned()
            .collect();
        events.streams.push(tx);
        (missed, rx)
    }

    fn deliver(&self, message: Value, line: String) {
        let response = message.get("method").is_none()
            && (message.get("result").is_some() || message.get("error").is_some());
        let waiter = message
            .get("id")
            .filter(|_| response)
            .and_then(|id| lock(&self.waiters).remove(&id_key(id)));
        match waiter {
            Some(tx) => {
                let _gone = tx.send(message);
            }
            None => self.publish(line),
        }
    }

    fn publish(&self, line: String) {
        let mut events = lock(&self.events);
        events.next += 1;
        let event = (events.next, line);
        events.log.push_back(event.clone());
        while events.log.len() > self.replay {
            events.log.pop_front();
        }
        events.streams.retain(|s| s.try_send(event.clone()).is_ok());
    }

    /// Ends the session: the child is killed, waiting requests fail and
    /// event streams close.
    pub(crate) fn end(&self) {
        self.alive.store(false, Ordering::Release);
        lock(&self.waiters).clear();
        lock(&self.events).streams.clear();
        if let Some(mut child) = lock(&self.child).take() {
            let _killed = child.kill();
            // Reaped off the caller's thread, so it is not left a zombie.
            std::thread::spawn(move || child.wait());
        }
    }
}

/// Reads the server's lines until it exits, then ends the session. A
/// line over `max` bytes, or one that is not JSON, ends it too: the
/// stream can no longer be trusted to be in step.
fn read(stdout: ChildStdout, session: &Session, max: usize) {
    let mut lines = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let got = (&mut lines).take(max as u64 + 1).read_line(&mut line);
        let Ok(n @ 1..) = got else { break };
        if n > max || !line.ends_with('\n') {
            break;
        }
        let text = line.trim_end();
        if text.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(text) else {
            break;
        };
        session.deliver(message, text.to_owned());
    }
    session.end();
}

impl Drop for Session {
    /// A session dropped without [`Session::end`] still stops its process.
    fn drop(&mut self) {
        self.end();
    }
}
