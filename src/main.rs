use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};

use nix::sys::signal::raise;
use nix::unistd::ForkResult::{Child, Parent};
use nix::unistd::{fork, getpid};

use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let err = ptrace::attach(getpid()).unwrap_err();
    if err == Errno::ENOSYS {
        return;
    }

    match unsafe { fork() }.expect("Failed to fork") {
        Parent { child } => {
            // Parent process
            println!("Parent: Forked child with PID {}", child);

            // Monitor syscalls in a loop
            loop {
                match waitpid(child, None).expect("Failed to wait for child process") {
                    WaitStatus::PtraceSyscall(pid) => {
                        let regs = ptrace::getregs(pid).expect("Failed to get registers");
                        let syscall = regs.orig_rax as i64;
                        println!("Parent: Intercepted syscall {}", syscall);

                        // Continue the child process to the next syscall
                        ptrace::syscall(pid, None).expect("Failed to continue syscall");
                    }
                    WaitStatus::Exited(_, status) => {
                        println!("Parent: Child exited with status {}", status);
                        break;
                    }
                    _ => {}
                }

                ptrace::syscall(child, None).unwrap();
            }
        }

        Child => {
            // Child process
            println!("Child: Started");

            println!("Child: enable traceme");
            ptrace::traceme().unwrap();

            println!("Child: SIGSTOP");
            raise(Signal::SIGSTOP).unwrap();

            // Execute a simple command (e.g., "ls")
            let args: Vec<String> = std::env::args().skip(1).collect();
            if args.is_empty() {
                eprintln!("No command provided");
                std::process::exit(1);
            }

            println!("Child: Executing command: {:?}", args);

            Command::new(&args[0]).args(&args[1..]).exec();
        }
    }
}
