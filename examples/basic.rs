use std::arch::asm;

use framehop::{
    x86_64::UnwindRegsX86_64, CacheNative, MayAllocateDuringUnwind, MustNotAllocateDuringUnwind,
    Unwinder, UnwinderNative,
};

fn main() {
    let objects = runwind::find_objects();
    println!("{:?}", objects);
    let mut cache = CacheNative::new();
    // let mut unwinder: UnwinderNative<_, MustNotAllocateDuringUnwind> = UnwinderNative::new();
    let mut unwinder: UnwinderNative<_, MayAllocateDuringUnwind> = UnwinderNative::new();
    for obj in &objects {
        unwinder.add_module(obj.to_module());
    }

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
        loop {
            let res = iter.next();
            println!("{res:?}");
            if res.is_err() || res == Ok(None) {
                break;
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
