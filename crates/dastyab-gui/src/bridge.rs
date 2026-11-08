//! Async bridge between the egui GUI and the tokio-` runtime.
//!
//! egui is synchronous: its `App::update` is called on the UI thread and
//! cannot block on async work without freezing the interface. This module is
//! the seam. It owns a single long-lived tokio runtime (kept in a `OnceLock`
//! so it outlives the app and is never dropped mid-frame), spawns async
//! "jobs" onto it, and delivers their results back to the GUI as
//! [`UiEvent`]s over an mpsc channel.
//!
//! # Why a global runtime (not one stored in `App`)
//! The app struct is dropped every time the window closes. If we stored the
//! [`Runtime`] inside it, `drop(app)` would shut the runtime down *mid-frame*,
//! and an in-flight future would panic with "runtime dropped". A `OnceLock`
//! runtime is leaked for the process lifetime, so spawned tasks always have a
//! live executor regardless of how many times the app is recreated.
//!
//! # Usage
//! ```
//! let (tx, rx) = bridge::channel();
//! bridge::spawn("deploy", tx.clone(), async {
//!     deploy_worker(token, pid).await
//! });
//! // in `update()`, call rx.try_recv() and handle UiEvent variants.
//! ```
//!
//! Every spawned job is tagged with a task name so the UI can show *which*
//! step failed (the [`UiEvent::TaskErr`] variant carries both the error and
//! the task name). This is what makes debugging in the GUI feel like the
//! Python version: no opaque failures, every error explains itself via
//! `CFError::explain()`.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use dastyab_core::CFError;

/// The single process-wide tokio runtime.
///
/// Created lazily on first use and never dropped for the lifetime of the
/// process. This is the fix for the "runtime dropped" panic class: the GUI
/// app struct can be created/destroyed freely without ever taking the
/// executor down with it.
fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| Runtime::new().expect("failed to create the DastYab tokio runtime"))
}

/// Channel flavour used by the bridge.
pub type Tx = mpsc::UnboundedSender<UiEvent>;
pub type Rx = mpsc::UnboundedReceiver<UiEvent>;

/// Create a bridge channel pair.
pub fn channel() -> (Tx, Rx) {
    mpsc::unbounded_channel()
}

/// A single event delivered from a background job to the GUI.
///
/// This is the *only* way background work talks to the UI. Keeping it a
/// closed enum means `update()` can match exhaustively and the compiler will
/// force us to handle every outcome — no silent swallowing of errors.
#[derive(Debug)]
pub enum UiEvent {
    /// A background job finished successfully, carrying a human summary.
    Done { task: String, summary: String },
    /// A background job failed. The error is the structured `CFError`, so
    /// the GUI can show title/detail/fix (matching the Python experience).
    TaskErr { task: String, error: CFError },
    /// Producers can stream progressive log lines into the live log pane.
    Log { task: String, line: String },
}

/// Spawn a future onto the global runtime, delivering its outcome to `tx`.
///
/// The job's result must be `Result<T, CFError>` where `T: ToString` — the
/// bridge automatically converts a successful `T` into a `UiEvent::Done`
/// summary and a `CFError` into a `UiEvent::TaskErr` carrying the task name.
/// This keeps every GUI action on the "error explains itself" path.
///
/// Returns a handle so a caller can abort if it ever needs to.
pub fn spawn<T, F, E>(task: &str, tx: Tx, fut: F) -> tokio::task::JoinHandle<()>
where
    T: ToString,
    F: Future<Output = Result<T, E>> + Send + 'static,
    E: Into<CFError> + Send + 'static,
{
    let task = task.to_string();
    runtime().spawn(async move {
        match fut.await {
            Ok(ok) => {
                let _ = tx.send(UiEvent::Done {
                    task,
                    summary: ok.to_string(),
                });
            }
            Err(e) => {
                let _ = tx.send(UiEvent::TaskErr {
                    task,
                    error: e.into(),
                });
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The very first bridge test DeepSeek asked for: a future that returns
    /// `Err(CFError::test())` must arrive as `UiEvent::TaskErr` with the task
    /// name populated.
    #[test]
    fn test_spawn_converts_err_to_task_err() {
        let (tx, mut rx) = channel();

        spawn("deploy", tx, async {
            Err::<String, CFError>(CFError::test())
        });

        // block a little for the spawned task to run
        let event = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(200));
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match rx.try_recv() {
                    Ok(ev) => return Some(ev),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                    Err(_) => return None,
                }
                if std::time::Instant::now() > deadline {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        });

        match event {
            Some(UiEvent::TaskErr { task, error }) => {
                assert_eq!(task, "deploy");
                assert_eq!(error.title, "Test error");
            }
            other => panic!("expected TaskErr, got {other:?}"),
        }
    }
}
