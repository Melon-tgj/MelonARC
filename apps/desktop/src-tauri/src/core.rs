//! The core process this window hosts.
//!
//! The shell starts one `melonarc-core`, watches it, restarts it when it dies
//! and stops it when the window closes. It is a host, not a supervisor daemon:
//! there is one child, one thread that ticks twice a second, and a state that
//! the page can read.
//!
//! The state machine has four wire names — `starting`, `running`, `stopped`,
//! `crashed` — and three rules:
//!
//! * a child that is alive but has not answered `/v1/status` yet is `starting`;
//!   it gets [`STARTUP_BUDGET`] to become `running`, then it is killed and the
//!   attempt counts as a failure;
//! * a failure waits [`backoff_for`] (1s, 2s, then 5s) and tries again, up to
//!   [`MAX_FAILURES`] consecutive failures; the next one is `crashed` and the
//!   supervisor stops trying until the user asks for a restart;
//! * reaching `running` clears the failure count, so a core that crashes once a
//!   week keeps being restarted.
//!
//! Everything the child prints goes to `<data-dir>/core.log`: a desktop launch
//! has no console, and throwing the core's diagnostics away would make every
//! failure unexplainable. There is no rotation yet (a recorded follow-up).
//!
//! Shutdown is deliberately blunt on Unix: `kill -TERM <pid>` through the
//! external `kill`, then a three second wait, then `Child::kill`. The standard
//! library has no signal API, and the no-new-crate rule is worth more here than
//! a tidy `libc::kill`.

use crate::api;
use crate::settings::{self, Settings};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a spawned core may take to answer before the attempt fails.
pub const STARTUP_BUDGET: Duration = Duration::from_secs(15);

/// The supervisor's tick. Half a second is fast enough to notice an exit and
/// slow enough to be invisible in a process list.
pub const TICK: Duration = Duration::from_millis(500);

/// Consecutive failures after which the supervisor gives up.
pub const MAX_FAILURES: u32 = 5;

/// How long a child gets to exit after `SIGTERM` before it is killed.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Starting,
    Running,
    Stopped,
    Crashed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Running => "running",
            State::Stopped => "stopped",
            State::Crashed => "crashed",
        }
    }
}

/// What `core_status` and `core_restart` return.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CoreStatus {
    pub state: String,
    /// `None` while no child exists — never a made up number.
    pub pid: Option<u32>,
    /// When the current child was spawned, in milliseconds since the epoch.
    pub started_at_unix_ms: Option<u64>,
    /// Automatic restarts in this shell session.
    pub restarts: u32,
    /// English technical detail. The page translates what it shows; this line is
    /// for a bug report, so it is never a user-facing sentence.
    pub detail: String,
}

/// What the supervisor does after a failed attempt: wait, or give up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitAction {
    Restart(Duration),
    GiveUp,
}

/// The backoff sequence: 1s, 2s, then 5s forever.
pub fn backoff_for(failures: u32) -> Duration {
    match failures {
        0 | 1 => Duration::from_secs(1),
        2 => Duration::from_secs(2),
        _ => Duration::from_secs(5),
    }
}

/// Five consecutive failures is the budget; the fifth one ends the retries.
pub fn gives_up(failures: u32) -> bool {
    failures >= MAX_FAILURES
}

pub fn after_failure(failures: u32) -> ExitAction {
    if gives_up(failures) {
        ExitAction::GiveUp
    } else {
        ExitAction::Restart(backoff_for(failures))
    }
}

/// What to do about a child that exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartupVerdict {
    /// It answered; promote it.
    Running,
    /// Still within its budget.
    Pending,
    /// Dead, or out of budget.
    Failed,
}

pub fn startup_verdict(alive: bool, ready: bool, elapsed: Duration) -> StartupVerdict {
    if !alive {
        return StartupVerdict::Failed;
    }
    if ready {
        return StartupVerdict::Running;
    }
    if elapsed >= STARTUP_BUDGET {
        StartupVerdict::Failed
    } else {
        StartupVerdict::Pending
    }
}

/// A handle the Tauri commands and the exit hook share.
#[derive(Clone)]
pub struct CoreHandle {
    shared: Arc<Shared>,
}

struct Shared {
    state: Mutex<Inner>,
    wake: Condvar,
}

struct Inner {
    /// Frozen at start-up: the token path and the API address belong to the
    /// window's client and only change when the shell restarts.
    settings: Settings,
    log_path: PathBuf,
    /// Re-resolved on every launch, so a new `core_path` / `core_config` takes
    /// effect without a shell restart.
    core_path: Option<PathBuf>,
    core_config: PathBuf,
    state: State,
    detail: String,
    pid: Option<u32>,
    started_at_ms: Option<u64>,
    restarts: u32,
    failures: u32,
    child: Option<Child>,
    spawned_at: Option<Instant>,
    restart_at: Option<Instant>,
    stopping: bool,
}

impl CoreHandle {
    /// Start the supervisor and make the first attempt. Missing pieces are not
    /// fatal: they become a `stopped` status with a detail that says what was
    /// looked for.
    pub fn start(settings: &Settings) -> CoreHandle {
        let inner = Inner {
            settings: settings.clone(),
            log_path: settings.core_log_path(),
            core_path: settings.core_path.clone(),
            core_config: settings.core_config.clone(),
            state: State::Stopped,
            detail: String::new(),
            pid: None,
            started_at_ms: None,
            restarts: 0,
            failures: 0,
            child: None,
            spawned_at: None,
            restart_at: None,
            stopping: false,
        };

        let shared = Arc::new(Shared {
            state: Mutex::new(inner),
            wake: Condvar::new(),
        });

        {
            let mut inner = lock(&shared);
            launch(&mut inner);
        }

        let handle = CoreHandle {
            shared: Arc::clone(&shared),
        };
        // A thread that cannot be created leaves the first child unmanaged; the
        // window still works, and the state says `starting` forever, which is
        // honest about what happened.
        let _ = thread::Builder::new()
            .name(String::from("core-supervisor"))
            .spawn(move || monitor(shared));
        handle
    }

    pub fn status(&self) -> CoreStatus {
        snapshot(&lock(&self.shared))
    }

    /// Stop the child, forget the failure count, re-resolve the two core paths
    /// and start again. This is the button the overview shows when the core is
    /// stopped or crashed.
    pub fn restart(&self) -> CoreStatus {
        let mut inner = lock(&self.shared);
        if inner.stopping {
            return snapshot(&inner);
        }

        terminate_child(&mut inner);
        inner.failures = 0;
        inner.restart_at = None;

        let (core_path, core_config) = settings::core_targets(&inner.settings);
        inner.core_path = core_path;
        inner.core_config = core_config;

        launch(&mut inner);
        snapshot(&inner)
    }

    /// Called from the exit hook: no more restarts, and the child goes away
    /// before the process does.
    pub fn shutdown(&self) {
        let mut inner = lock(&self.shared);
        if inner.stopping {
            return;
        }
        inner.stopping = true;
        inner.restart_at = None;
        terminate_child(&mut inner);
        inner.state = State::Stopped;
        inner.detail = String::from("the shell is exiting");
        drop(inner);
        self.shared.wake.notify_all();
    }
}

#[tauri::command]
pub fn core_status(core: tauri::State<CoreHandle>) -> CoreStatus {
    core.status()
}

#[tauri::command]
pub fn core_restart(core: tauri::State<CoreHandle>) -> CoreStatus {
    core.restart()
}

fn lock(shared: &Shared) -> MutexGuard<'_, Inner> {
    // A panic elsewhere must not turn every later command into a panic of its
    // own: the state is a plain record, so the guard is recovered.
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn monitor(shared: Arc<Shared>) {
    loop {
        {
            let guard = lock(&shared);
            if guard.stopping {
                return;
            }
            let (guard, _) = shared
                .wake
                .wait_timeout(guard, TICK)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if guard.stopping {
                return;
            }
        }
        tick(&mut lock(&shared));
    }
}

fn tick(inner: &mut Inner) {
    if inner.stopping {
        return;
    }

    // 1. A child that exited on its own is a failure, whether it had reached
    //    `running` or was still starting. The wait is taken out of the state
    //    first so the failure branch can write to it without two borrows.
    let waited = match inner.child.as_mut() {
        Some(child) => Some(child.try_wait()),
        None => None,
    };
    match waited {
        Some(Ok(Some(status))) => {
            let detail = describe_exit(&status);
            forget_child(inner);
            record_failure(inner, detail);
            return;
        }
        Some(Ok(None)) => {}
        Some(Err(error)) => {
            forget_child(inner);
            record_failure(inner, format!("cannot read the process state: {error}"));
            return;
        }
        None => {}
    }

    // 2. Something is running: promote it when it answers, or fail the attempt
    //    when its budget is gone. A child that already reached `running` is not
    //    probed again — the exit check above is what watches it from here on,
    //    and the window's own polling is the health signal.
    if inner.child.is_some() {
        if inner.state == State::Running {
            return;
        }
        let elapsed = inner.spawned_at.map(|at| at.elapsed()).unwrap_or_default();
        let probe = api::probe_status(&inner.settings);
        match startup_verdict(true, probe.is_ok(), elapsed) {
            StartupVerdict::Running => {
                inner.state = State::Running;
                inner.failures = 0;
                inner.detail.clear();
            }
            StartupVerdict::Pending => {}
            StartupVerdict::Failed => {
                let detail = match probe {
                    Ok(()) => format!(
                        "the core did not answer within the {}s start-up budget",
                        STARTUP_BUDGET.as_secs()
                    ),
                    Err(error) => format!(
                        "the core did not become ready within {}s: {}",
                        STARTUP_BUDGET.as_secs(),
                        error.detail
                    ),
                };
                terminate_child(inner);
                record_failure(inner, detail);
            }
        }
        return;
    }

    // 3. Nothing is running: start the pending attempt when its delay is over.
    if inner.state == State::Crashed {
        return;
    }
    let Some(at) = inner.restart_at else {
        return;
    };
    if Instant::now() < at {
        return;
    }
    inner.restart_at = None;
    inner.restarts += 1;

    let (core_path, core_config) = settings::core_targets(&inner.settings);
    inner.core_path = core_path;
    inner.core_config = core_config;
    launch(inner);
}

/// One attempt: resolve what is missing, then spawn.
fn launch(inner: &mut Inner) {
    inner.restart_at = None;
    inner.pid = None;
    inner.started_at_ms = None;
    inner.spawned_at = None;

    let Some(core_path) = inner.core_path.clone() else {
        inner.state = State::Stopped;
        inner.detail = settings::core_missing_detail(&inner.settings.stored.core_path);
        return;
    };

    if !inner.core_config.is_file() {
        inner.state = State::Stopped;
        inner.detail = format!(
            "the core configuration is missing: {} (set core_config in {})",
            inner.core_config.display(),
            inner.settings.settings_path.display()
        );
        return;
    }

    match spawn_child(inner, &core_path) {
        Ok(()) => {
            inner.state = State::Starting;
            inner.detail.clear();
        }
        Err(error) => {
            inner.state = State::Stopped;
            inner.detail = error;
        }
    }
}

fn spawn_child(inner: &mut Inner, core_path: &Path) -> Result<(), String> {
    if let Some(parent) = inner.log_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }

    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&inner.log_path)
        .map_err(|error| format!("cannot open {}: {error}", inner.log_path.display()))?;
    let stdout = log
        .try_clone()
        .map_err(|error| format!("cannot share {}: {error}", inner.log_path.display()))?;

    // `-api-listen` is always passed: the shell and the core must agree on the
    // address the token is sent to, and the shell validated it already. This
    // overrides whatever the configuration file says, on purpose.
    let child = Command::new(core_path)
        .arg("-config")
        .arg(&inner.core_config)
        .arg("-api-listen")
        .arg(&inner.settings.api_label)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(log))
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", core_path.display()))?;

    inner.pid = Some(child.id());
    inner.started_at_ms = Some(now_ms());
    inner.spawned_at = Some(Instant::now());
    inner.child = Some(child);
    Ok(())
}

/// Drop every trace of the child that just went away. The state stays whatever
/// the failure branch decides next.
fn forget_child(inner: &mut Inner) {
    inner.child = None;
    inner.pid = None;
    inner.started_at_ms = None;
    inner.spawned_at = None;
}

fn record_failure(inner: &mut Inner, detail: String) {
    inner.failures += 1;
    inner.detail = detail;
    match after_failure(inner.failures) {
        ExitAction::GiveUp => {
            inner.state = State::Crashed;
            inner.restart_at = None;
            inner.detail = format!(
                "{} ({} consecutive failures; no further attempt is made until a restart is requested)",
                inner.detail, inner.failures
            );
        }
        ExitAction::Restart(delay) => {
            // The next attempt is already scheduled, so `starting` is the honest
            // state: nothing is running, but something is about to be.
            inner.state = State::Starting;
            inner.restart_at = Some(Instant::now() + delay);
            inner.detail = format!("{}; restarting in {}s", inner.detail, delay.as_secs());
        }
    }
}

/// Take the child out of the state and stop it, politely first.
fn terminate_child(inner: &mut Inner) {
    let Some(mut child) = inner.child.take() else {
        inner.pid = None;
        return;
    };
    terminate_process(&mut child);
    inner.pid = None;
    inner.started_at_ms = None;
    inner.spawned_at = None;
}

#[cfg(unix)]
fn terminate_process(child: &mut Child) {
    // The standard library has no signal API and this stage adds no crate, so
    // the polite request goes through the system `kill`. A failure here (no
    // such binary, no permission) is not fatal: the hard kill below still runs.
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();

    let deadline = Instant::now() + SHUTDOWN_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate_process(child: &mut Child) {
    // Windows has no `SIGTERM` to send; terminating the process is the only
    // option the standard library offers.
    let _ = child.kill();
    let _ = child.wait();
}

fn describe_exit(status: &ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("the core was terminated by signal {signal}");
        }
    }
    match status.code() {
        Some(code) => format!("the core exited with status {code}"),
        None => String::from("the core exited"),
    }
}

fn snapshot(inner: &Inner) -> CoreStatus {
    CoreStatus {
        state: inner.state.as_str().to_string(),
        pid: inner.pid,
        started_at_unix_ms: inner.started_at_ms,
        restarts: inner.restarts,
        detail: inner.detail.clone(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_sequence_is_one_two_then_five_seconds() {
        assert_eq!(backoff_for(1), Duration::from_secs(1));
        assert_eq!(backoff_for(2), Duration::from_secs(2));
        assert_eq!(backoff_for(3), Duration::from_secs(5));
        assert_eq!(backoff_for(4), Duration::from_secs(5));
        assert_eq!(backoff_for(9), Duration::from_secs(5), "the delay is capped");
    }

    #[test]
    fn five_consecutive_failures_end_the_retries() {
        assert_eq!(after_failure(1), ExitAction::Restart(Duration::from_secs(1)));
        assert_eq!(after_failure(2), ExitAction::Restart(Duration::from_secs(2)));
        assert_eq!(after_failure(3), ExitAction::Restart(Duration::from_secs(5)));
        assert_eq!(after_failure(4), ExitAction::Restart(Duration::from_secs(5)));
        assert_eq!(after_failure(5), ExitAction::GiveUp);
        assert_eq!(after_failure(6), ExitAction::GiveUp);
        assert!(gives_up(MAX_FAILURES));
        assert!(!gives_up(MAX_FAILURES - 1));
    }

    #[test]
    fn a_child_is_promoted_only_when_it_answers_inside_its_budget() {
        assert_eq!(
            startup_verdict(true, true, Duration::from_millis(600)),
            StartupVerdict::Running
        );
        assert_eq!(
            startup_verdict(true, false, Duration::from_millis(600)),
            StartupVerdict::Pending
        );
        assert_eq!(
            startup_verdict(true, false, STARTUP_BUDGET),
            StartupVerdict::Failed
        );
        assert_eq!(
            startup_verdict(false, true, Duration::from_millis(10)),
            StartupVerdict::Failed,
            "a dead process is a failure even if it once answered"
        );
    }

    #[test]
    fn the_wire_state_names_are_the_contract() {
        assert_eq!(State::Starting.as_str(), "starting");
        assert_eq!(State::Running.as_str(), "running");
        assert_eq!(State::Stopped.as_str(), "stopped");
        assert_eq!(State::Crashed.as_str(), "crashed");
    }

    #[test]
    fn a_status_without_a_child_reports_nulls_instead_of_numbers() {
        let settings = crate::settings::resolve(crate::settings::Inputs {
            stored: crate::settings::Overrides::default(),
            settings_path: PathBuf::from("/tmp/melonarc-test/melonarc/shell.json"),
            env: &|_| None,
            exists: &|_| false,
            search_paths: vec![],
        })
        .unwrap();

        let inner = Inner {
            settings,
            log_path: PathBuf::from("/tmp/melonarc-test/melonarc/core.log"),
            core_path: None,
            core_config: PathBuf::from("/tmp/melonarc-test/melonarc/melonarc.conf"),
            state: State::Stopped,
            detail: String::from("no core binary"),
            pid: None,
            started_at_ms: None,
            restarts: 0,
            failures: 0,
            child: None,
            spawned_at: None,
            restart_at: None,
            stopping: false,
        };

        let status = snapshot(&inner);
        assert_eq!(status.state, "stopped");
        assert!(status.pid.is_none());
        assert!(status.started_at_unix_ms.is_none());
        assert_eq!(status.restarts, 0);
        assert_eq!(status.detail, "no core binary");
    }

    #[test]
    fn a_status_without_a_binary_says_what_it_looked_for() {
        let settings = crate::settings::resolve(crate::settings::Inputs {
            stored: crate::settings::Overrides::default(),
            settings_path: PathBuf::from("/tmp/melonarc-test/melonarc/shell.json"),
            env: &|_| None,
            exists: &|_| false,
            search_paths: vec![],
        })
        .unwrap();

        let mut inner = Inner {
            settings,
            log_path: PathBuf::from("/tmp/melonarc-test/melonarc/core.log"),
            core_path: None,
            core_config: PathBuf::from("/tmp/melonarc-test/melonarc/melonarc.conf"),
            state: State::Stopped,
            detail: String::new(),
            pid: None,
            started_at_ms: None,
            restarts: 0,
            failures: 0,
            child: None,
            spawned_at: None,
            restart_at: None,
            stopping: false,
        };

        launch(&mut inner);
        assert_eq!(inner.state, State::Stopped);
        assert!(inner.detail.starts_with("no melonarc-core binary"), "{}", inner.detail);
    }

    #[test]
    fn launching_without_a_configuration_file_stops_before_spawning() {
        let settings = crate::settings::resolve(crate::settings::Inputs {
            stored: crate::settings::Overrides::default(),
            settings_path: PathBuf::from("/tmp/melonarc-test/melonarc/shell.json"),
            env: &|_| None,
            exists: &|path| path == Path::new("/tmp/melonarc-test/melonarc/melonarc-core"),
            search_paths: vec![PathBuf::from("/tmp/melonarc-test/melonarc/melonarc-core")],
        })
        .unwrap();

        let mut inner = Inner {
            settings,
            log_path: PathBuf::from("/tmp/melonarc-test/melonarc/core.log"),
            core_path: Some(PathBuf::from("/tmp/melonarc-test/melonarc/melonarc-core")),
            core_config: PathBuf::from("/tmp/melonarc-test/melonarc/missing.conf"),
            state: State::Stopped,
            detail: String::new(),
            pid: None,
            started_at_ms: None,
            restarts: 0,
            failures: 0,
            child: None,
            spawned_at: None,
            restart_at: None,
            stopping: false,
        };

        launch(&mut inner);
        assert_eq!(inner.state, State::Stopped);
        assert!(inner.detail.contains("configuration is missing"), "{}", inner.detail);
        assert!(inner.child.is_none(), "nothing was spawned");
    }
}
