use std::ffi::CString;

use nix::NixPath;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Injection {
    #[serde(flatten)]
    pub matcher: Matcher,

    #[serde(flatten)]
    pub injector: Injector,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FsSyscall {
    folder: CString,
    recursive: u8,
    syscall: u64,
    pid: libc::pid_t,
}

#[repr(C, packed)]
pub struct RawFsSyscall {
    folder: libc::c_int,
    recursive: u8,
    syscall: u64,
    pid: libc::pid_t,
}

impl Into<RawFsSyscall> for FsSyscall {
    fn into(self) -> RawFsSyscall {
        let fd = if self.folder.len() > 0 {
            unsafe { libc::open(self.folder.as_ptr(), libc::O_DIRECTORY) }
        } else {
            0
        };

        return RawFsSyscall {
            folder: fd,
            recursive: self.recursive,
            syscall: self.syscall,
            pid: self.pid,
        };
    }
}

impl Drop for RawFsSyscall {
    fn drop(&mut self) {
        if self.folder != 0 {
            unsafe { libc::close(self.folder) };
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlkIo {
    dev: CString,
}

#[repr(C, packed)]
pub struct RawBlkIo {
    dev: u32,
}

impl Into<RawBlkIo> for BlkIo {
    fn into(self) -> RawBlkIo {
        let fd = if self.dev.len() > 0 {
            unsafe { libc::open(self.dev.as_ptr(), libc::O_DIRECTORY) }
        } else {
            return RawBlkIo { dev: 0 };
        };
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };

        // TODO: handle errors for the following syscall
        unsafe {libc::fstat(fd, &mut stat)};
        unsafe {libc::close(fd)};
        RawBlkIo {
            dev: stat.st_dev as u32,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "matcher", rename_all = "snake_case")]
pub enum Matcher {
    FsSyscall(FsSyscall),
    BlkIo(BlkIo),
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct Delay {
    delay: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "injector", rename_all = "snake_case")]
pub enum Injector {
    Delay(Delay),
}
