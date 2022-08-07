#![allow(deprecated)]

use std::{
    ffi::CStr,
    io::Write,
    mem::{self, ManuallyDrop},
    slice,
};

use libc::{
    _dyld_get_image_header, _dyld_get_image_name, _dyld_image_count, load_command, mach_header_64,
    segment_command_64, LC_SEGMENT_64, MH_MAGIC_64,
};
use log::{info, warn};
use memmap2::Mmap;
use once_cell::sync::Lazy;

use super::Object;

static OBJECTS: Lazy<Vec<Object>> = Lazy::new(find_objects);

pub fn get_objects() -> &'static [Object] {
    &OBJECTS
}

fn find_objects() -> Vec<Object> {
    let mut objects = Vec::new();
    let n = unsafe { _dyld_image_count() };
    for i in 0..n {
        if let Some(obj) = unsafe { load_object(i) } {
            objects.push(obj);
        }
    }
    objects
}

unsafe fn load_object(image_index: u32) -> Option<Object> {
    let name = _dyld_get_image_name(image_index);
    if name.is_null() {
        return None;
    }
    let name = CStr::from_ptr(name);
    info!("load object: {name:?}");

    let header = _dyld_get_image_header(image_index);
    if header.is_null() {
        return None;
    }
    if (*header).magic != MH_MAGIC_64 {
        warn!("not a mach64 object");
        return None;
    }
    let header = header as *const mach_header_64;

    // let endian = NativeEndian;
    // let header = &*(header as *const macho::MachHeader64<NativeEndian>);
    // let data = core::slice::from_raw_parts(
    //     header as *const _ as *const u8,
    //     mem::size_of_val(header) + header.sizeofcmds.get(endian) as usize,
    // );
    // let mut f = std::fs::File::create("/tmp/a.bin").unwrap();
    // f.write_all(data).unwrap();
    // std::process::exit(0);
    // let mut load_commands = header.load_commands(endian, data, 0).ok()?;
    // while let Some(cmd) = load_commands.next().ok()? {
    //     info!("{:?}", cmd);
    // }

    let ncmds = (*header).ncmds as usize;
    let mut cmd_header_addr = header as usize + mem::size_of::<mach_header_64>();
    for i in 0..ncmds {
        let cmd_header = cmd_header_addr as *const load_command;
        if (*cmd_header).cmd != LC_SEGMENT_64 {
            continue;
        }
        let cmd = &*(cmd_header_addr as *const segment_command_64);
        let cmd_size = cmd.cmdsize as usize;
        let seg_name = CStr::from_ptr(&cmd.segname as *const _);
        info!("cmd 0x{:x} {} {:?}", cmd.cmd, cmd_size, seg_name);

        if seg_name.to_bytes() == b"__TEXT" {
        }

        cmd_header_addr += cmd_size;
    }

    None
}

pub struct ObjectMmap {
    pub mmap: ManuallyDrop<Mmap>,
    pub obj_file: ManuallyDrop<object::File<'static, &'static [u8]>>,
}
