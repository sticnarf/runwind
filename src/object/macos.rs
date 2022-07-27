use std::ffi::{CStr, OsString};
use std::os::unix::prelude::OsStringExt;
use std::path::PathBuf;
use std::{mem, slice};

use log::warn;
use object::macho;
use object::read::macho::{MachHeader, Segment as _};
use object::NativeEndian;
use once_cell::sync::Lazy;

use super::{Object, ObjectMmap, ObjectPhdr, Segment};

static OBJECTS: Lazy<Vec<Object>> = Lazy::new(find_objects);

pub fn get_objects() -> &'static [Object] {
    &OBJECTS
}

fn find_objects() -> Vec<Object> {
    let mut objects = Vec::new();
    let n = unsafe { libc::_dyld_image_count() };
    for i in 0..n {
        if let Some(obj) = load_object(i) {
            objects.push(obj);
        }
    }
    objects
}

fn load_object(i: u32) -> Option<Object> {
    // Fetch the name of this library which corresponds to the path of
    // where to load it as well.
    let path = unsafe {
        let name = libc::_dyld_get_image_name(i);
        if name.is_null() {
            return None;
        }
        PathBuf::from(OsString::from_vec(CStr::from_ptr(name).to_bytes().to_vec()))
    };
    println!("{:?}", path);

    let header = unsafe { libc::_dyld_get_image_header(i).as_ref()? };
    if header.magic != macho::MH_MAGIC_64 {
        return None;
    }
    let header = unsafe { &*(header as *const _ as *const macho::MachHeader64<NativeEndian>) };
    let data = unsafe {
        slice::from_raw_parts(
            header as *const _ as *const u8,
            mem::size_of_val(header) + header.sizeofcmds.get(NativeEndian) as usize,
        )
    };
    let mut load_commands = header.load_commands(NativeEndian, data, 0).ok()?;

    let mut text = None;
    let mut text_fileoff_zero = false;
    while let Some(cmd) = load_commands.next().ok()? {
        if let Some((seg, _)) = cmd.segment_64().ok()? {
            if seg.name() == b"__TEXT" {
                if text.is_some() {
                    warn!("Multiple text segments found in {path:?}");
                }
                text = Some(Segment {
                    p_vaddr: seg.vmaddr(NativeEndian).try_into().ok()?,
                    p_memsz: seg.vmsize(NativeEndian).try_into().ok()?,
                });
                if seg.fileoff(NativeEndian) == 0 && seg.filesize(NativeEndian) > 0 {
                    text_fileoff_zero = true;
                }
            }
        }
    }

    // Determine the "slide" for this library which ends up being the
    // bias we use to figure out where in memory objects are loaded.
    // This is a bit of a weird computation though and is the result of
    // trying a few things in the wild and seeing what sticks.
    //
    // The general idea is that the `bias` plus a segment's
    // `stated_virtual_memory_address` is going to be where in the
    // actual address space the segment resides. The other thing we rely
    // on though is that a real address minus the `bias` is the index to
    // look up in the symbol table and debuginfo.
    //
    // It turns out, though, that for system loaded libraries these
    // calculations are incorrect. For native executables, however, it
    // appears correct. Lifting some logic from LLDB's source it has
    // some special-casing for the first `__TEXT` section loaded from
    // file offset 0 with a nonzero size. For whatever reason when this
    // is present it appears to mean that the symbol table is relative
    // to just the vmaddr slide for the library. If it's *not* present
    // then the symbol table is relative to the the vmaddr slide plus
    // the segment's stated address.
    //
    // To handle this situation if we *don't* find a text section at
    // file offset zero then we increase the bias by the first text
    // sections's stated address and decrease all stated addresses by
    // that amount as well. That way the symbol table is always appears
    // relative to the library's bias amount. This appears to have the
    // right results for symbolizing via the symbol table.
    //
    // Honestly I'm not entirely sure whether this is right or if
    // there's something else that should indicate how to do this. For
    // now though this seems to work well enough (?) and we should
    // always be able to tweak this over time if necessary.
    //
    // For some more information see #318

    let mut text = text?;

    let base_addr = text.p_vaddr;

    text.p_vaddr = 0;

    // let mut slide = unsafe { libc::_dyld_get_image_vmaddr_slide(i) as usize };
    // println!("slide: 0x{:x}, {text_fileoff_zero}", slide);
    // if !text_fileoff_zero {
    //     let adjust = text.p_vaddr;
    //     for segment in segments.iter_mut() {
    //         segment.p_vaddr -= adjust;
    //     }
    //     slide += adjust;
    // }

    let phdr = ObjectPhdr {
        base_addr,
        path,
        text,
    };

    let mmap = ObjectMmap::new(&phdr.path)?;

    Some(Object { phdr, mmap })
}
