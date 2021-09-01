use anyhow::Result;
use nix::{
    fcntl::{open, OFlag},
    ioctl_none,
    sys::{ioctl, stat::Mode},
};

use std::os::raw::c_int;

const CHAOS_IOCTL_MAGIC: u8 = 0xC1;
pub struct Client {
    fd: c_int,
}

ioctl_none!(chaos_driver_get_version, CHAOS_IOCTL_MAGIC, 0);

impl Client {
    pub fn build() -> Result<Self> {
        let fd = open("/dev/chaos", OFlag::empty(), Mode::empty())?;
        return Ok(Client { fd: fd });
    }

    pub fn get_version(&self) -> Result<i32> {
        return Ok(unsafe { chaos_driver_get_version(self.fd)? });
    }
}
