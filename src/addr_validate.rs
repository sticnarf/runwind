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
    use super::*;

    #[test]
    fn validate_stack() {
        let i = 0;

        assert!(validate(&i as *const _ as *const libc::c_void));
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
}
