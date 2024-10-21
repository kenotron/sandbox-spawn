use std::ffi::CString;

use anyhow::{Context, Error};
use env_logger::Env;
use libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK};
use log::{debug, error, info, warn};
use nix::{
    errno::Errno,
    sys::{
        ptrace::{self, Options},
        signal::Signal,
        wait::{wait, waitpid, WaitStatus},
    },
    unistd::{execve, fork, getpid, ForkResult, Pid},
};

fn main() {
    let logger_env = Env::default().default_filter_or("info");
    env_logger::Builder::from_env(logger_env).init();

    info!("started with pid {}", getpid());

    match unsafe { fork() } {
        Ok(ForkResult::Child) => run_child(),
        Ok(ForkResult::Parent { child }) => run_parent(child),
        Err(e) => panic!("Could not fork main process: {}", e),
    };
}

/*
 * The child process will become the soon-to-be tracee
 */
fn run_child() {
    info!("child process executing as {}", getpid());

    // the pid won't change with exec, so we ask to be traced
    ptrace::traceme().expect("OS could not be bothered to trace me");

    let path = CString::new("/usr/local/share/nvm/versions/node/v20.11.0/bin/node").unwrap();
    let args = vec![
        CString::new("node").unwrap(),
        CString::new("index.js").unwrap(),
    ];
    let env_vars: Vec<CString> = vec![];

    execve(&path, &args, &env_vars).expect("Child failed to execute");

    // let e = Command::new("./target/debug/testee").exec();

    // let e = Command::new("./target/debug/forker").exec();

    // let e = Command::new("/usr/local/share/nvm/versions/node/v20.11.0/bin/node")
    //     .arg("index.js").exec();

    // let e = Command::new("/usr/lib/jvm/java-17-openjdk/bin/java")
    //     .arg("-jar")
    //     .arg("jvm-test/target/jvm-test-1.0-SNAPSHOT-jar-with-dependencies.jar")
    //     .exec();

    // raise(Signal::SIGSTOP).expect("Child failed to stop itself");
}

fn run_parent(pid: Pid) {
    // wait for our child process to be ready
    let ws = wait().expect("Parent failed waiting for child");
    info!("Child process ready with signal: {ws:?}, will ask it to continue until syscall");

    setup_tracing(pid).expect("Parent failed tracing");
    trace_syscall(pid, None).expect("Parent failed tracing");

    loop {
        match wait_for_signal(pid) {
            Ok(true) => break,
            Ok(false) => { /* nop */ }
            Err(e) => {
                match e {
                    SandboxTracerError::Ptrace(e) => error!("PtraceError: {e}"),
                }
                break;
            }
        }
    }
}

fn read_cstring(pid: nix::unistd::Pid, addr: *const i8) -> Option<String> {
    let mut bytes = Vec::new();
    let mut current_addr = addr as usize;

    loop {
        let word = ptrace::read(pid, current_addr as *mut _).ok()?;
        let word_bytes = word.to_ne_bytes();

        for &byte in &word_bytes {
            if byte == 0 {
                return Some(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.push(byte);
        }

        current_addr += std::mem::size_of::<usize>();
    }
}

fn wait_for_signal(child: Pid) -> Result<bool, SandboxTracerError> {
    match wait() {
        Ok(WaitStatus::Stopped(pid_t, sig_num)) => {
            info!("Child with pid: {} stopped with signal", pid_t);
            // handle_child_stopped(sig_num, pid_t, msync_counter)
            // trace_syscall(pid_t, None)

            Ok(false)
        }
        Ok(WaitStatus::Exited(pid, exit_status)) => {
            info!("Child with pid: {} exited with status {}", pid, exit_status);
            Ok(child == pid)
        }

        Ok(WaitStatus::Continued(pid)) => {
            info!("Child with pid: {} continued", pid);
            Ok(false)
        }

        Ok(WaitStatus::Signaled(pid, signal, core_dumped)) => {
            info!(
                "Child with pid: {} signaled with signal {}, core_dumped? {}",
                pid, signal as i8, core_dumped
            );
            Ok(false)
        }

        Ok(WaitStatus::PtraceEvent(pid, signal, event)) => {
            /*
                We receive a PtraceEvent with SIGTRAP when the child forks.
                In this case, we instruct linux to notify us again, should that child fork
                Then we wait for syscalls in the process to happen.
            */
            debug!("PtraceEvent - for: {}, {} ", pid, event);

            if event == PTRACE_EVENT_FORK {
                info!("Child forked, will trace it");
                trace_syscall(pid, None)?;
            } else if event == PTRACE_EVENT_VFORK {
                info!("Child vforked, will trace it");
                trace_syscall(pid, None)?;
            } else if event == PTRACE_EVENT_CLONE {
                let new_pid_int = ptrace::getevent(pid).expect("Parent: Cannot get event") as i32;
                let new_pid = Pid::from_raw(new_pid_int);

                info!("Child cloned, will trace it {}", new_pid);

                // continue on the new child process because ptrace automatically SIGSTOPs
                waitpid(new_pid, None).unwrap();

                ptrace::syscall(pid, None).unwrap();
                ptrace::syscall(new_pid, None).unwrap();
            } else if event == PTRACE_EVENT_EXEC {
                info!("Child executed, will trace it");
                trace_syscall(pid, None)?;
            } else {
                trace_syscall(pid, signal)?;
            }

            Ok(false)
        }

        Ok(WaitStatus::PtraceSyscall(pid)) => {
            debug!("PtraceSyscall - for: {}", pid);

            let regs = ptrace::getregs(pid).expect("Failed to get registers");
            let syscall = regs.orig_rax as i64;

            if syscall == libc::SYS_write {
                let fd = regs.rdi as i32;

                // now find the file name in /proc/[pid]/[fd]
                let fd_path = format!("/proc/{}/fd/{}", pid, fd);
                let filename = std::fs::read_link(fd_path).unwrap();
                info!("[{}] Write filename = {}", pid, filename.to_str().unwrap());

                ptrace::syscall(pid, None).unwrap();
            } else if syscall == libc::SYS_read {
                let fd = regs.rdi as i32;

                // now find the file name in /proc/[pid]/[fd]
                let fd_path = format!("/proc/{}/fd/{}", pid, fd);
                let filename = std::fs::read_link(fd_path).unwrap();
                info!("[{}] Read filename = {}", pid, filename.to_str().unwrap());

                ptrace::syscall(pid, None).unwrap();
            } else if syscall == libc::SYS_open {
                let filename_ptr = regs.rdi as *const i8;

                if !filename_ptr.is_null() {
                    let filename = read_cstring(pid, filename_ptr).unwrap();
                    info!("[{}]: Open filename = {}", pid, filename);
                }

                ptrace::syscall(pid, None).unwrap();
            } else if syscall == libc::SYS_openat {
                let filename_ptr = regs.rsi as *const i8;

                if !filename_ptr.is_null() {
                    let filename = read_cstring(pid, filename_ptr).unwrap();
                    info!("[{}] Openat filename = {}", pid, filename);
                }

                ptrace::syscall(pid, None).unwrap();
            } else if syscall == libc::SYS_fstat {
                let fd = regs.rdi as i32;

                // now find the file name in /proc/[pid]/[fd]
                let fd_path = format!("/proc/{}/fd/{}", pid, fd);
                let filename = std::fs::read_link(fd_path).unwrap();
                info!("[{}] Fstat filename = {}", pid, filename.to_str().unwrap());
                ptrace::syscall(pid, None).unwrap();
            } else if syscall == libc::SYS_lstat || syscall == libc::SYS_stat {
                let filename_ptr = regs.rdi as *const i8;

                if !filename_ptr.is_null() {
                    let filename = read_cstring(pid, filename_ptr).unwrap();
                    info!("[{}] Stat filename = {}", pid, filename);
                }

                ptrace::syscall(pid, None).unwrap();
            } else {
                // info!("[{}] Other Syscall {}", pid, syscall);
                ptrace::syscall(pid, None).unwrap();
            }

            Ok(false)
        }
        Ok(status) => {
            warn!("Received unhandled wait status: {:?}", status);
            ptrace::syscall(child, None).unwrap();
            Ok(false)
        }

        Err(e) => {
            if e == Errno::ECHILD {
                return Ok(false);
            }

            if e == Errno::ESRCH {
                return Ok(false);
            }

            Err(SandboxTracerError::Ptrace(Error::from(e)))
        }
    }
}

/// Setup the preace options to also trace fork, clone and vfork
fn setup_tracing(pid: Pid) -> Result<(), SandboxTracerError> {
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACEFORK
            .union(Options::PTRACE_O_TRACECLONE)
            .union(Options::PTRACE_O_TRACEVFORK)
            .union(Options::PTRACE_O_TRACESYSGOOD)
            .union(Options::PTRACE_O_TRACEEXEC)
            .union(Options::PTRACE_O_EXITKILL),
    )
    .context("Could not set options to follow forks")
    .map_err(SandboxTracerError::Ptrace)
}

/// Allow the child to execute to the next syscall
fn trace_syscall<T: Into<Option<Signal>>>(pid: Pid, sig: T) -> Result<(), SandboxTracerError> {
    ptrace::syscall(pid, sig)
        .context("Could not trace to next syscall")
        .map_err(SandboxTracerError::Ptrace)
}

#[derive(Debug)]
enum SandboxTracerError {
    // Wait(Errno),
    // Register(Errno),
    Ptrace(Error),
    // Proc(ProcError),
}
