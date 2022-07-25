use std::{
    cell::RefCell,
    mem::{size_of, MaybeUninit},
};

use libc::{c_int, c_void};

thread_local! {
    static MEM_VALIDATE_PIPE: RefCell<[i32; 2]> = RefCell::new([-1, -1]);
}

#[inline]
#[cfg(target_os = "linux")]
fn create_pipe() -> Result<(c_int, c_int), c_int> {
    use libc::{pipe2, O_CLOEXEC, O_NONBLOCK};

    let mut pipefd = [0; 2];
    let res = unsafe { pipe2(&mut pipefd as _, O_CLOEXEC | O_NONBLOCK) };
    if res == 0 {
        Ok((pipefd[0], pipefd[1]))
    } else {
        Err(res)
    }
}

#[inline]
#[cfg(target_os = "macos")]
fn create_pipe() -> nix::Result<(i32, i32)> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    use nix::unistd::pipe;
    use std::os::unix::io::RawFd;

    fn set_flags(fd: RawFd) -> nix::Result<()> {
        let mut flags = FdFlag::from_bits(fcntl(fd, FcntlArg::F_GETFD)?).unwrap();
        flags |= FdFlag::FD_CLOEXEC;
        fcntl(fd, FcntlArg::F_SETFD(flags))?;
        let mut flags = OFlag::from_bits(fcntl(fd, FcntlArg::F_GETFL)?).unwrap();
        flags |= OFlag::O_NONBLOCK;
        fcntl(fd, FcntlArg::F_SETFL(flags))?;
        Ok(())
    }

    let (read_fd, write_fd) = pipe()?;
    set_flags(read_fd)?;
    set_flags(write_fd)?;
    Ok((read_fd, write_fd))
}

fn open_pipe() -> Result<(), c_int> {
    MEM_VALIDATE_PIPE.with(|pipes| {
        let mut pipes = pipes.borrow_mut();

        // ignore the result
        let _ = unsafe { libc::close(pipes[0]) };
        let _ = unsafe { libc::close(pipes[1]) };

        let (read_fd, write_fd) = create_pipe()?;

        pipes[0] = read_fd;
        pipes[1] = write_fd;

        Ok(())
    })
}

pub fn validate(addr: *const libc::c_void) -> bool {
    const CHECK_LENGTH: usize = 2 * size_of::<*const libc::c_void>() / size_of::<u8>();

    // read data in the pipe
    let valid_read = MEM_VALIDATE_PIPE.with(|pipes| {
        let pipes = pipes.borrow();
        loop {
            let mut buf: MaybeUninit<[c_void; CHECK_LENGTH]> = MaybeUninit::uninit();

            let res = unsafe { libc::read(pipes[0], buf.as_mut_ptr() as _, CHECK_LENGTH as _) };
            if res >= 0 {
                break res > 0;
            } else if res == libc::EINTR as _ {
                continue;
            } else if res == libc::EAGAIN as _ {
                break true;
            } else {
                break false;
            }
        }
    });

    if !valid_read && open_pipe().is_err() {
        return false;
    }

    MEM_VALIDATE_PIPE.with(|pipes| {
        let pipes = pipes.borrow();
        loop {
            let res = unsafe { libc::write(pipes[1], addr, CHECK_LENGTH) };
            if res >= 0 {
                break res > 0;
            } else if res == libc::EINTR as _ {
                continue;
            } else {
                break false;
            }
        }
    })
}

#[cfg(test)]
mod test {
    use std::{arch::asm, ptr};

    use super::*;

    #[test]
    fn validate_stack() {
        let i = 0;
        println!("{:p}", &i as *const _);

        let sp: u64;
        let mut stackaddr: *mut libc::c_void = ptr::null_mut();

        unsafe {
            asm!(
                "mov {sp}, rsp",
                sp = out(reg) sp,
            );
            let mut attr: MaybeUninit<libc::pthread_attr_t> = MaybeUninit::uninit();
            let res = libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr());
            if res != 0 {
                println!("unable to get attr: {res}");
                return;
            }
            let attr = attr.assume_init();
            let mut stacksize: libc::size_t = 0;
            let res =
                libc::pthread_attr_getstack(&attr as _, &mut stackaddr as _, &mut stacksize as _);
            if res != 0 {
                println!("unable to get stack: {res}");
                return;
            }
            println!("bottom: {stackaddr:p}, top: 0x{sp:x} {stacksize}");
        }

        assert!(validate(&i as *const _ as *const libc::c_void));
        for addr in stackaddr as usize..sp as usize {
            assert!(validate(addr as *const libc::c_void));
        }
    }

    #[test]
    fn validate_heap() {
        let vec = vec![0; 1000];

        for i in vec.iter() {
            assert!(validate(i as *const _ as *const libc::c_void));
        }
    }

    #[test]
    fn failed_validate() {
        assert!(!validate(std::ptr::null::<libc::c_void>()));
        assert!(!validate(-1_i32 as usize as *const libc::c_void))
    }

    #[test]
    fn bench_validate() {
        let i = 0;

        let begin = std::time::Instant::now();
        for _ in 0..10000 {
            let mut attr: MaybeUninit<libc::pthread_attr_t> = MaybeUninit::uninit();
            // let res = unsafe { libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) };
            // if res != 0 {
            //     println!("unable to get attr: {res}");
            //     return;
            // }
            unsafe { libc::pthread_self() };
            // let sp: u64;
            // let mut stackaddr: *mut libc::c_void = ptr::null_mut();

            // unsafe {
            //     asm!(
            //         "mov {sp}, rsp",
            //         sp = out(reg) sp,
            //     );
            //     let mut attr: MaybeUninit<libc::pthread_attr_t> = MaybeUninit::uninit();
            //     let res = libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr());
            //     if res != 0 {
            //         println!("unable to get attr: {res}");
            //         return;
            //     }
            //     let attr = attr.assume_init();
            //     let mut stacksize: libc::size_t = 0;
            //     let res = libc::pthread_attr_getstack(
            //         &attr as _,
            //         &mut stackaddr as _,
            //         &mut stacksize as _,
            //     );
            //     if res != 0 {
            //         println!("unable to get stack: {res}");
            //         return;
            //     }
            //     let bottom = stackaddr as usize + stacksize;
            //     let ptr = &i as *const _ as usize;
            //     assert!(ptr > sp as usize && ptr < bottom);
            // }
        }
        println!("{:?}", begin.elapsed() / 10000);
    }
}
