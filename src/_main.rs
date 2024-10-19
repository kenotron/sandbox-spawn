// use libc::AT_FDCWD;
// use nix::{
//     sched::{unshare, CloneFlags},
//     sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags},
// };
// use std::{os::fd::AsRawFd, process::Command};

// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // Unshare the mount namespace
//     unshare(CloneFlags::CLONE_NEWNS).expect("Failed to unshare");

//     let group = Fanotify::init(
//         // InitFlags::FAN_CLASS_NOTIF,
//         // EventFFlags::O_RDWR | EventFFlags::O_APPEND,
//         InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK,
//         EventFFlags::O_RDONLY
//             | EventFFlags::O_LARGEFILE
//             | EventFFlags::O_CLOEXEC
//             | EventFFlags::O_NOATIME,
//     )
//     .unwrap();

//     // create a PathBuf pointing at /home/vscode/fan/
//     let tempfile = std::path::PathBuf::from("/workspaces/teams-modular-packages/packages/components/components-flyout-for-you-page");

//     group
//         .mark(
//             MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
//             MaskFlags::FAN_MODIFY
//                 | MaskFlags::FAN_CLOSE
//                 | MaskFlags::FAN_OPEN
//                 | MaskFlags::FAN_ACCESS,
//             Some(AT_FDCWD),
//             Some(&tempfile),
//         )
//         .unwrap();

//     // execute a child process "node index.js", place this in unsafe block
//     let mut child = Command::new("/usr/local/share/nvm/versions/node/v20.11.0/bin/node")
//         .arg("--max-old-space-size=8192")
//         .arg("--max-semi-space-size=64")
//         .arg("node_modules/jest/bin/jest.js")
//         .arg("packages/components/components-flyout-for-you-page/src/flyout-for-you-l2-page.rtl.test.tsx")
//         .arg("--config=/workspaces/teams-modular-packages/packages/components/components-flyout-for-you-page/jest.config.js")
//         .arg("--coverageThreshold={}")
//         .arg("--forceExit")
//         .arg("--verbose")
//         .arg("--coverage=false")
//         .arg("--no-cache")
//         .arg("--runInBand")
//         .current_dir("/workspaces/teams-modular-packages")
//         .spawn()
//         .expect("failed to execute child");

//     let ecode = child.wait().expect("failed to wait on child");

//     println!("ecode: {:?}", ecode);

//     let events = group.read_events().unwrap();

//     // print out all the events
//     for event in events.iter() {
//         // print out the file name that was modified
//         let fd_opt = event.fd();
//         let fd = fd_opt.as_ref().unwrap();
//         let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
//         println!("{:?}, {:?}", path, event.mask());
//     }

//     // assert!(event.check_version());
//     // assert_eq!(
//     //     event.mask(),
//     //     MaskFlags::FAN_OPEN
//     //         | MaskFlags::FAN_MODIFY
//     //         | MaskFlags::FAN_CLOSE_WRITE
//     // );

//     // let fd_opt = event.fd();
//     // let fd = fd_opt.as_ref().unwrap();
//     // let path = read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
//     // assert_eq!(path, tempfile);

//     // // read test file
//     // {
//     //     let mut f = File::open(&tempfile).unwrap();
//     //     let mut s = String::new();
//     //     f.read_to_string(&mut s).unwrap();
//     // }

//     // let mut events = group.read_events().unwrap();
//     // assert_eq!(events.len(), 1, "should have read exactly one event");
//     // let event = events.pop().unwrap();
//     // assert!(event.check_version());
//     // assert_eq!(
//     //     event.mask(),
//     //     MaskFlags::FAN_OPEN | MaskFlags::FAN_CLOSE_NOWRITE
//     // );
//     // let fd_opt = event.fd();
//     // let fd = fd_opt.as_ref().unwrap();
//     // let path = read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
//     // assert_eq!(path, tempfile);

//     Ok(())
// }

use nix::sys::ptrace;
use nix::sys::signal::{raise, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use std::fs::File;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ptrace <command> [args...]");
        std::process::exit(1);
    }

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process
            waitpid(child, None).expect("Failed to wait for child process");

            let seize_options = ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACESECCOMP
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_EXITKILL;

            ptrace::seize(child, seize_options).expect("Failed to seize to the child process");
            waitpid(child, None).expect("Failed to wait for child process");

            ptrace::cont(child, None).expect("Failed to continue the child process");

            loop {
                ptrace::syscall(child, None).expect("Failed to trace syscall");
                match waitpid(child, None).expect("Failed to wait for syscall") {
                    WaitStatus::Exited(_, _) => break,
                    WaitStatus::PtraceSyscall(pid) => {
                        let regs = ptrace::getregs(pid).expect("Failed to get registers");
                        let syscall = regs.orig_rax as i64;

                        if syscall == libc::SYS_open || syscall == libc::SYS_openat {
                            let filename_ptr = regs.rdi as *const i8;
                            let filename = unsafe { std::ffi::CStr::from_ptr(filename_ptr) }
                                .to_str()
                                .expect("Failed to read filename");

                            let mut file = File::create("file_accesses.log")
                                .expect("Failed to create log file");
                            writeln!(file, "Process {} accessed file: {}", pid, filename)
                                .expect("Failed to write to log file");
                        }

                        ptrace::syscall(pid, None).expect("Failed to trace syscall");
                    }
                    _ => {}
                }
            }
        }
        Ok(ForkResult::Child) => {
            // Child process
            println!("Child process started with PID: {}", std::process::id());
            ptrace::traceme().expect("Failed to traceme");
            raise(Signal::SIGSTOP).expect("Failed to stop the child process");

            let command = &args[1];
            let command_args = &args[2..];
            Command::new(command).args(command_args).exec();
        }
        Err(_) => {
            eprintln!("Fork failed");
            std::process::exit(1);
        }
    }
}
