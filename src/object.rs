use std::{
    env,
    ffi::{CStr, OsString},
    fmt::{self, Debug},
    fs::File,
    mem::ManuallyDrop,
    ops::Range,
    os::unix::prelude::OsStringExt,
    path::{Path, PathBuf},
    slice,
};

use framehop::{Module, ModuleSvmaInfo, ModuleUnwindData, TextByteData};
use libc::{c_int, c_void, dl_iterate_phdr, dl_phdr_info, size_t, PT_LOAD};
use log::warn;
use memmap2::Mmap;
use object::{Object as _, ObjectSection};

pub struct ObjectPhdr {
    base_addr: usize,
    path: PathBuf,
    text: Segment,
}

impl Debug for ObjectPhdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectPhdr")
            .field("base_addr", &(self.base_addr as *const c_void))
            .field("path", &self.path)
            .field("text", &self.text)
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

pub struct ObjectMmap {
    file: ManuallyDrop<File>,
    mmap: ManuallyDrop<Mmap>,
    obj_file: ManuallyDrop<object::File<'static, &'static [u8]>>,
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

pub struct Object {
    phdr: ObjectPhdr,
    mmap: ObjectMmap,
}

impl Object {
    fn section_range(&self, section_name: &str) -> Option<Range<u64>> {
        self.mmap
            .obj_file
            .section_by_name(section_name)
            .and_then(|s| s.file_range())
            .map(|(start, end)| start..(start + end))
    }

    fn range_data(&self, range: &Range<u64>) -> &[u8] {
        let (start, end) = (range.start as usize, range.end as usize);
        &self.mmap.mmap[start..end]
    }

    pub fn to_module(&self) -> Module<&'_ [u8]> {
        let name = self.phdr.path.to_string_lossy().to_string();
        let base_avma = self.mmap.mmap.as_ptr() as u64;
        let avma_range = base_avma..(base_avma + self.mmap.mmap.len() as u64);
        // FIXME: should be the vmaddr of the __TEXT segment for mach-O
        let base_svma = 0;
        let text = self.section_range(".text");
        let eh_frame_hdr = self.section_range(".eh_frame_hdr");
        let eh_frame = self.section_range(".eh_frame");
        let got = self.section_range(".got");
        let unwind_data = match (&eh_frame_hdr, &eh_frame_hdr) {
            (Some(eh_frame_hdr), Some(eh_frame)) => ModuleUnwindData::EhFrameHdrAndEhFrame(
                self.range_data(eh_frame_hdr),
                self.range_data(eh_frame),
            ),
            (None, Some(eh_frame)) => ModuleUnwindData::EhFrame(self.range_data(eh_frame)),
            _ => ModuleUnwindData::None,
        };
        let text_start = self.phdr.base_addr + self.phdr.text.p_vaddr;
        let text_bytes =
            unsafe { slice::from_raw_parts(text_start as *const u8, self.phdr.text.p_memsz) };
        let text_range = (text_start as u64)..((text_start + self.phdr.text.p_memsz) as u64);
        let text_data = TextByteData::new(text_bytes, text_range);
        Module::new(
            name,
            avma_range,
            base_avma,
            ModuleSvmaInfo {
                base_svma,
                text,
                text_env: None,
                stubs: None,
                stub_helper: None,
                eh_frame,
                eh_frame_hdr,
                got,
            },
            unwind_data,
            Some(text_data),
        )
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

    if let Some(mmap) = ObjectMmap::new(&path) {
        let objects = &mut *(data as *mut Vec<Object>);
        let phdr = ObjectPhdr {
            base_addr,
            path,
            text,
        };
        objects.push(Object { phdr, mmap });
    }

    0
}
