use libc::AT_FDCWD;
use nix::{
    sched::{unshare, CloneFlags},
    sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags},
};
use std::{os::fd::AsRawFd, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Unshare the mount namespace
     unshare(CloneFlags::CLONE_NEWNS)?;

    let group = Fanotify::init(InitFlags::FAN_CLASS_NOTIF, EventFFlags::O_RDONLY).unwrap();

    // create a PathBuf pointing at /home/vscode/fan/
    let tempfile = std::path::PathBuf::from("/home/vscode/fan");

    group
        .mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
            MaskFlags::FAN_MODIFY
                | MaskFlags::FAN_CLOSE_WRITE,
            Some(AT_FDCWD),
            Some(&tempfile),
        )
        .unwrap();

    // execute a child process "node index.js", place this in unsafe block
    let mut child = Command::new("/usr/local/share/nvm/versions/node/v20.11.0/bin/node")
        .arg("index.js")
        .spawn()
        .expect("failed to execute child");

    let ecode = child.wait().expect("failed to wait on child");

    println!("ecode: {:?}", ecode);

    let events = group.read_events().unwrap();

    // print out all the events
    for event in events.iter() {
        // print out the file name that was modified
        let fd_opt = event.fd();
        let fd = fd_opt.as_ref().unwrap();
        let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        println!("path: {:?}", path);
        println!("mask: {:?}", event.mask());
    }

    // assert!(event.check_version());
    // assert_eq!(
    //     event.mask(),
    //     MaskFlags::FAN_OPEN
    //         | MaskFlags::FAN_MODIFY
    //         | MaskFlags::FAN_CLOSE_WRITE
    // );

    // let fd_opt = event.fd();
    // let fd = fd_opt.as_ref().unwrap();
    // let path = read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
    // assert_eq!(path, tempfile);

    // // read test file
    // {
    //     let mut f = File::open(&tempfile).unwrap();
    //     let mut s = String::new();
    //     f.read_to_string(&mut s).unwrap();
    // }

    // let mut events = group.read_events().unwrap();
    // assert_eq!(events.len(), 1, "should have read exactly one event");
    // let event = events.pop().unwrap();
    // assert!(event.check_version());
    // assert_eq!(
    //     event.mask(),
    //     MaskFlags::FAN_OPEN | MaskFlags::FAN_CLOSE_NOWRITE
    // );
    // let fd_opt = event.fd();
    // let fd = fd_opt.as_ref().unwrap();
    // let path = read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
    // assert_eq!(path, tempfile);

    Ok(())
}
