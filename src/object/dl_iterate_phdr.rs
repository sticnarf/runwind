use std::{
    env,
    ffi::{CStr, OsString},
    fs::File,
    mem::ManuallyDrop,
    os::unix::prelude::OsStringExt,
    path::{Path, PathBuf},
    slice,
};

use libc::{c_int, c_void, dl_iterate_phdr, dl_phdr_info, size_t, PT_LOAD};
use log::warn;
use memmap2::Mmap;
use once_cell::sync::Lazy;

use super::{Object, ObjectPhdr, Segment};

static OBJECTS: Lazy<Vec<Object>> = Lazy::new(find_objects);

pub fn get_objects() -> &'static [Object] {
    &OBJECTS
}

fn find_objects() -> Vec<Object> {
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
    let info = &*info;
    let base_addr = info.dlpi_addr as usize;

    // The dlpi_name of the current executable is a empty C string.
    let path = if *info.dlpi_name == 0 {
        match env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                warn!("Could not get current executable path: {e}");
                return 0;
            }
        }
    } else {
        PathBuf::from(OsString::from_vec(
            CStr::from_ptr(info.dlpi_name).to_bytes().to_vec(),
        ))
    };
    let mut text = None;

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
                    warn!("Multiple text segments found in {path:?}");
                }
                text = Some(segment);
            }
            // Ignore other segments
            _ => {}
        }
    }

    let text = match text {
        Some(text) => text,
        None => {
            warn!("No text segment found in {path:?}");
            return 0;
        }
    };

    let phdr = ObjectPhdr {
        base_addr,
        path,
        text,
    };
    if let Some(mmap) = ObjectMmap::new(&phdr.path) {
        let objects = &mut *(data as *mut Vec<Object>);
        objects.push(Object { phdr, mmap });
    }

    0
}

pub struct ObjectMmap {
    pub file: ManuallyDrop<File>,
    pub mmap: ManuallyDrop<Mmap>,
    pub obj_file: ManuallyDrop<object::File<'static, &'static [u8]>>,
}

impl ObjectMmap {
    fn new(path: &Path) -> Option<ObjectMmap> {
        let file = File::open(path)
            .map_err(|e| warn!("Failed to open {path:?}: {e}"))
            .ok()?;
        let mmap = unsafe {
            Mmap::map(&file)
                .map_err(|e| warn!("Failed to mmap {path:?}: {e}"))
                .ok()?
        };
        let (ptr, len) = (mmap.as_ptr(), mmap.len());
        let data = unsafe { slice::from_raw_parts(ptr, len) };
        let obj_file = object::File::parse(data)
            .map_err(|e| warn!("Failed to parse {path:?}: {e}"))
            .ok()?;
        Some(ObjectMmap {
            file: ManuallyDrop::new(file),
            mmap: ManuallyDrop::new(mmap),
            obj_file: ManuallyDrop::new(obj_file),
        })
    }
}

impl Drop for ObjectMmap {
    fn drop(&mut self) {
        // Specify drop order:
        // 1. Drop the object::File that may reference the mmap.
        // 2. Drop the mmap.
        // 3. Close the file.
        unsafe {
            ManuallyDrop::drop(&mut self.obj_file);
            ManuallyDrop::drop(&mut self.mmap);
            ManuallyDrop::drop(&mut self.file);
        };
    }
}
