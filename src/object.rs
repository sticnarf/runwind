use std::{
    env,
    ffi::{CStr, OsString},
    fmt::{self, Debug},
    os::unix::prelude::OsStringExt,
    slice,
};

use libc::{c_int, c_void, dl_iterate_phdr, dl_phdr_info, size_t, PT_GNU_EH_FRAME, PT_LOAD};
use log::warn;

pub struct Object {
    base_addr: usize,
    name: OsString,
    text: Segment,
    eh_frame_hdr: Option<Segment>,
}

impl Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Object")
            .field("base_addr", &(self.base_addr as *const c_void))
            .field("name", &self.name)
            .field("text", &self.text)
            .field("eh_frame_hdr", &self.eh_frame_hdr)
            .finish()
    }
}

pub struct Segment {
    p_vaddr: usize,
    p_memsz: usize,
}

impl Debug for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Segment")
            .field("p_vaddr", &(self.p_vaddr as *const c_void))
            .field("p_memsz", &self.p_memsz)
            .finish()
    }
}

pub fn find_objects() -> Vec<Object> {
    let mut objects = Vec::new();
    unsafe {
        dl_iterate_phdr(
            Some(iterate_phdr_cb),
            &mut objects as *mut Vec<Object> as *mut c_void,
        );
    }
    objects
}

/// An executable segment.
const PF_X: u32 = 1;
/// A readable segment.
const PF_R: u32 = 4;

unsafe extern "C" fn iterate_phdr_cb(
    info: *mut dl_phdr_info,
    _size: size_t,
    data: *mut c_void,
) -> c_int {
    let objects = &mut *(data as *mut Vec<Object>);

    let info = &*info;
    let base_addr = info.dlpi_addr as usize;

    // The dlpi_name of the current executable is a empty C string.
    let name = if *info.dlpi_name == 0 {
        match env::current_exe() {
            Ok(path) => path.into_os_string(),
            Err(e) => {
                warn!("Could not get current executable path: {e}");
                return 0;
            }
        }
    } else {
        OsString::from_vec(CStr::from_ptr(info.dlpi_name).to_bytes().to_vec())
    };

    let mut text = None;
    let mut eh_frame_hdr = None;

    let phdrs = slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);
    for phdr in phdrs {
        let segment = Segment {
            p_vaddr: phdr.p_vaddr as usize,
            p_memsz: phdr.p_memsz as usize,
        };
        match phdr.p_type {
            // .text segment
            PT_LOAD if phdr.p_flags == PF_X | PF_R => {
                if text.is_some() {
                    warn!("Multiple text segments found in {name:?}");
                }
                text = Some(segment);
            }
            // .eh_frame_hdr segment
            PT_GNU_EH_FRAME => {
                if text.is_some() {
                    warn!("Multiple eh_frame_hdr segments found in {name:?}");
                }
                eh_frame_hdr = Some(segment);
            }
            // Ignore other segments
            _ => {}
        }
    }

    if let Some(text) = text {
        objects.push(Object {
            base_addr,
            name,
            text,
            eh_frame_hdr,
        });
    } else {
        warn!("No text segment found in {name:?}");
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let objects = find_objects();
        println!("{objects:#?}");
    }
}
