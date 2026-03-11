use syscalls::{Sysno, syscall};

fn has_kernelsu_legacy() -> u32 {
    let mut version = 0;
    const CMD_GET_VERSION: i32 = 2;
    unsafe {
        let _ = syscall!(
            Sysno::prctl,
            0xDEADBEEF,
            CMD_GET_VERSION,
            std::ptr::addr_of_mut!(version)
        );
    }

    version
}

fn has_kernelsu_v2() -> u32 {
    const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
    const KSU_INSTALL_MAGIC2: u32 = 0xCAFEBABE;
    const KSU_IOCTL_GET_INFO: u32 = 0x80004b02; // _IOC(_IOC_READ, 'K', 2, 0)

    #[repr(C)]
    #[derive(Default)]
    struct GetInfoCmd {
        version: u32,
        flags: u32,
        features: u32,
    }

    // Try new method: get driver fd using reboot syscall with magic numbers
    let mut fd: i32 = -1;
    unsafe {
        let _ = syscall!(
            Sysno::reboot,
            KSU_INSTALL_MAGIC1,
            KSU_INSTALL_MAGIC2,
            0,
            std::ptr::addr_of_mut!(fd)
        );
    }

    if fd < 0 {
        return 0;
    }

    // New method: try to get version info via ioctl
    let mut cmd = GetInfoCmd::default();
    let version = unsafe {
        let ret = syscall!(Sysno::ioctl, fd, KSU_IOCTL_GET_INFO, &mut cmd as *mut _);

        match ret {
            Ok(_) => cmd.version,
            Err(_) => 0,
        }
    };

    unsafe {
        let _ = syscall!(Sysno::close, fd);
    }

    version
}

pub fn has_kernelsu() -> u32 {
    let version = has_kernelsu_v2();
    if version == 0 {
        has_kernelsu_legacy()
    } else {
        version
    }
}
