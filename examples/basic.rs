use addr2line::Context;
use log::LevelFilter;
use runwind::{CacheNative, MustNotAllocateDuringUnwind, Unwinder};
use simplelog::{ColorChoice, TermLogger, TerminalMode};

fn main() {
    TermLogger::init(
        LevelFilter::Info,
        Default::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let objects = runwind::get_objects();
    println!("{objects:?}");

    let mut cache = CacheNative::new();
    let unwinder = Unwinder::<MustNotAllocateDuringUnwind>::new();
    let mut contexts = Vec::new();
    for obj in runwind::get_objects() {
        if let Some(file) = obj.obj_file() {
            let context = Context::new(file).unwrap();
            contexts.push((obj.base_addr(), obj.text_svma(), context));
        }
    }
    contexts.sort_by_key(|(base_addr, _, _)| *base_addr);

    a(|| {
        let mut iter = unwinder.iter_frames(&mut cache);
        let mut frame_addresses = Vec::new();
        loop {
            match iter.try_next() {
                Ok(Some(addr)) => frame_addresses.push(addr),
                Ok(None) => break,
                Err(e) => {
                    println!("{e}");
                    break;
                }
            }
        }
        for addr in frame_addresses.iter().skip(1) {
            println!("frame: 0x{:x}", addr);
            let addr = *addr as u64;
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
                                println!("address 0x{:x} not in text section", addr);
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
