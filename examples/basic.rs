use std::{arch::asm, mem::MaybeUninit, ptr};

use addr2line::Context;
use framehop::{
    x86_64::UnwindRegsX86_64, CacheNative, MustNotAllocateDuringUnwind, Unwinder, UnwinderNative,
};

fn main() {
    let objects = runwind::find_objects();
    println!("{:?}", objects);
    let mut cache = CacheNative::new();
    let mut unwinder: UnwinderNative<_, MustNotAllocateDuringUnwind> = UnwinderNative::new();
    let mut contexts = Vec::new();
    for obj in &objects {
        unwinder.add_module(obj.to_module());
        let context = Context::new(obj.obj_file()).unwrap();
        contexts.push((obj.base_addr(), obj.text_svma(), context));
    }
    contexts.sort_by_key(|(base_addr, _, _)| *base_addr);

    a(|| {
        let ip: u64;
        let sp: u64;
        let bp: u64;
        unsafe {
            asm!(
                "lea {ip}, [rip]",
                "mov {sp}, rsp",
                "mov {bp}, rbp",
                ip = out(reg) ip,
                sp = out(reg) sp,
                bp = out(reg) bp,
            );
        }

        unsafe {
            let mut attr: MaybeUninit<libc::pthread_attr_t> = MaybeUninit::uninit();
            let res = libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr());
            if res != 0 {
                println!("unable to get attr: {res}");
                return;
            }
            let attr = attr.assume_init();
            let mut stackaddr: *mut libc::c_void = ptr::null_mut();
            let mut stacksize: libc::size_t = 0;
            let res =
                libc::pthread_attr_getstack(&attr as _, &mut stackaddr as _, &mut stacksize as _);
            if res != 0 {
                println!("unable to get stack: {res}");
                return;
            }
            println!("bottom: {stackaddr:p}, top: 0x{sp:x} {stacksize}");
        }

        let mut read_stack = |addr| {
            println!("read stack {:x}", addr);
            unsafe { Ok(((addr / 8 * 8) as *const u64).read()) }
        };
        let mut iter = unwinder.iter_frames(
            ip,
            UnwindRegsX86_64::new(ip, sp, bp),
            &mut cache,
            &mut read_stack,
        );
        let mut frame_addresses = Vec::new();
        loop {
            match iter.next() {
                Ok(Some(addr)) => frame_addresses.push(addr),
                Ok(None) => break,
                Err(e) => {
                    println!("{e}");
                    return;
                }
            }
        }
        for addr in frame_addresses {
            let addr = addr.address();
            let (svma, context) =
                match contexts.binary_search_by_key(&addr, |(base_addr, _, _)| *base_addr as u64) {
                    Ok(_) => {
                        println!("address shouldn't be equal to base address!");
                        return;
                    }
                    Err(idx) => {
                        if idx == 0 {
                            println!("no module is found");
                            return;
                        } else {
                            let (base_addr, text_range, context) = &contexts[idx - 1];
                            let svma = addr as usize - base_addr;
                            if !text_range.contains(&svma) {
                                println!("address not in text section");
                                return;
                            }
                            (svma, context)
                        }
                    }
                };
            let mut frames = context.find_frames(svma as u64).unwrap();
            loop {
                match frames.next() {
                    Ok(Some(frame)) => {
                        println!("{:?}", frame.function.as_ref().map(|f| f.demangle()));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        println!("{e}");
                    }
                }
            }
        }
    });
}

fn a(f: impl FnOnce()) {
    b(f);
}

fn b(f: impl FnOnce()) {
    c(f);
}

fn c(f: impl FnOnce()) {
    d(f);
}

fn d(f: impl FnOnce()) {
    f();
}
