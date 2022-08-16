use std::{
    env,
    ffi::{CStr, OsString},
    fmt::{self, Debug},
    fs::File,
    mem,
    mem::ManuallyDrop,
    ops::Range,
    os::unix::prelude::OsStringExt,
    path::{Path, PathBuf},
    slice,
};

use framehop::{Module, ModuleSvmaInfo, ModuleUnwindData, TextByteData};
use gimli::{BaseAddresses, EhFrameHdr, NativeEndian, Pointer};
use libc::{c_int, c_void, dl_iterate_phdr, dl_phdr_info, size_t, PT_GNU_EH_FRAME, PT_LOAD};
use log::warn;
use memmap2::Mmap;
use object::{Object as _, ObjectSection};
use once_cell::sync::Lazy;

use super::Segment;

pub struct Object {
    path: PathBuf,
    base_addr: usize,
    text: Segment,
    unwind_data: UnwindData,
}

impl Object {
    pub fn to_module(&self) -> Module<&'_ [u8]> {
        let name = self.path.to_string_lossy().to_string();
        let base_avma = self.base_addr as u64;
        let text_range = (self.base_addr + self.text.p_vaddr) as u64
            ..(self.base_addr + self.text.p_vaddr + self.text.p_memsz) as u64;
        let text_bytes = unsafe {
            slice::from_raw_parts(
                (self.base_addr + self.text.p_vaddr) as *const u8,
                self.text.p_memsz,
            )
        };
        let text_data = TextByteData::new(text_bytes, text_range.clone());

        match &self.unwind_data {
            UnwindData::Mmap(mmap) => {
                let eh_frame_hdr = mmap.section_range(".eh_frame_hdr");
                let eh_frame = mmap.section_range(".eh_frame");
                let unwind_data = match (&eh_frame_hdr, &eh_frame) {
                    (Some(eh_frame_hdr), Some(eh_frame)) => ModuleUnwindData::EhFrameHdrAndEhFrame(
                        mmap.range_data(eh_frame_hdr),
                        mmap.range_data(eh_frame),
                    ),
                    (None, Some(eh_frame)) => ModuleUnwindData::EhFrame(mmap.range_data(eh_frame)),
                    _ => ModuleUnwindData::None,
                };
                Module::new(
                    name,
                    text_range,
                    base_avma,
                    ModuleSvmaInfo {
                        base_svma: 0,
                        text: mmap.section_range(".text"),
                        text_env: None,
                        stubs: None,
                        stub_helper: None,
                        eh_frame,
                        eh_frame_hdr,
                        got: mmap.section_range(".got"),
                    },
                    unwind_data,
                    Some(text_data),
                )
            }
            UnwindData::EhFrame(data) => {
                todo!()
            }
        }
    }

    pub fn obj_file(&self) -> Option<&'_ object::File<'static, &'static [u8]>> {
        match &self.unwind_data {
            UnwindData::Mmap(mmap) => Some(&*mmap.obj_file),
            UnwindData::EhFrame(_) => None,
        }
    }

    pub fn base_addr(&self) -> usize {
        self.base_addr
    }

    pub fn text_svma(&self) -> Range<usize> {
        self.text.p_vaddr..(self.text.p_vaddr + self.text.p_memsz)
    }
}

impl Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Object")
            .field("path", &self.path)
            .field("base_addr", &(self.base_addr as *const c_void))
            .field("text", &self.text)
            .field("unwind_data", &self.unwind_data)
            .finish()
    }
}

pub enum UnwindData {
    Mmap(ObjectMmap),
    EhFrame(EhFrameData),
}

impl Debug for UnwindData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mmap(_) => f.debug_tuple("Mmap").finish(),
            Self::EhFrame(_) => f.debug_tuple("EhFrame").finish(),
        }
    }
}

pub struct EhFrameData {
    eh_frame_hdr: Range<u64>,
    eh_frame: Range<u64>,
}

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
                    warn!("Multiple .text segments found in {path:?}");
                }
                text = Some(segment);
            }
            // .eh_frame_hdr segment
            PT_GNU_EH_FRAME => {
                if eh_frame_hdr.is_some() {
                    warn!("Multiple .eh_frame_hdr segments found in {path:?}");
                }
                eh_frame_hdr = Some(segment);
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

    let unwind_data = if let Some(mmap) = ObjectMmap::new(&path) {
        UnwindData::Mmap(mmap)
    } else if let Some(data) =
        eh_frame_hdr.and_then(|eh_frame_hdr| find_eh_frame(base_addr, eh_frame_hdr))
    {
        // If we cannot mmap the file, find the eh_frame from the memory according to .eh_frame_hdr
        UnwindData::EhFrame(data)
    } else {
        warn!("Cannot mmap or find .eh_frame of {path:?}");
        return 0;
    };
    let objects = &mut *(data as *mut Vec<Object>);
    objects.push(Object {
        path,
        base_addr,
        text,
        unwind_data,
    });
    0
}

pub struct ObjectMmap {
    pub file: ManuallyDrop<File>,
    pub mmap: ManuallyDrop<Mmap>,
    pub obj_file: ManuallyDrop<object::File<'static, &'static [u8]>>,
}

impl ObjectMmap {
    fn new(path: &Path) -> Option<ObjectMmap> {
        // let file = File::open(path)
        //     .map_err(|e| warn!("Failed to open {path:?}: {e}"))
        //     .ok()?;
        // let mmap = unsafe {
        //     Mmap::map(&file)
        //         .map_err(|e| warn!("Failed to mmap {path:?}: {e}"))
        //         .ok()?
        // };
        // let (ptr, len) = (mmap.as_ptr(), mmap.len());
        // let data = unsafe { slice::from_raw_parts(ptr, len) };
        // let obj_file = object::File::parse(data)
        //     .map_err(|e| warn!("Failed to parse {path:?}: {e}"))
        //     .ok()?;
        // Some(ObjectMmap {
        //     file: ManuallyDrop::new(file),
        //     mmap: ManuallyDrop::new(mmap),
        //     obj_file: ManuallyDrop::new(obj_file),
        // })
        None
    }

    fn section_range(&self, section_name: &str) -> Option<Range<u64>> {
        self.obj_file
            .section_by_name(section_name)
            .and_then(|s| s.file_range())
            .map(|(start, end)| start..(start + end))
    }

    fn range_data(&self, range: &Range<u64>) -> &[u8] {
        let (start, end) = (range.start as usize, range.end as usize);
        &self.mmap[start..end]
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

unsafe fn find_eh_frame(base_addr: usize, eh_frame_hdr_segment: Segment) -> Option<EhFrameData> {
    let eh_frame_hdr_data = slice::from_raw_parts(
        (base_addr + eh_frame_hdr_segment.p_vaddr) as *const u8,
        eh_frame_hdr_segment.p_memsz,
    );
    let eh_frame_hdr = EhFrameHdr::new(eh_frame_hdr_data, NativeEndian)
        .parse(
            &BaseAddresses::default()
                .set_eh_frame_hdr((base_addr + eh_frame_hdr_segment.p_vaddr) as u64),
            mem::size_of::<usize>() as u8,
        )
        .ok()?;
    let eh_frame_ptr: usize = match eh_frame_hdr.eh_frame_ptr() {
        Pointer::Direct(ptr) => ptr.try_into().ok()?,
        Pointer::Indirect(_) => return None,
    };
    let mut cie_ptr = eh_frame_ptr;
    loop {
        let len_ptr = cie_ptr as *const u32;
        let mut fde_ptr = if (*len_ptr) == 0 {
            break;
        } else if (*len_ptr) == 0xffffffff {
            let ext_len_ptr = (cie_ptr + 4) as *const u64;
            cie_ptr + 4 + 8 + (*ext_len_ptr) as usize
        } else {
            cie_ptr + 4 + (*len_ptr) as usize
        };
        loop {
            let len_ptr = fde_ptr as *const u32;
            if (*len_ptr) == 0 {
                cie_ptr = fde_ptr + 4;
                break;
            } else if (*len_ptr) == 0xffffffff {
                let ext_len_ptr = (fde_ptr + 4) as *const u64;
                fde_ptr += 4 + 8 + (*ext_len_ptr) as usize;
            } else {
                fde_ptr += 4 + (*len_ptr) as usize
            }
        }
    }
    let eh_frame_data =
        slice::from_raw_parts(eh_frame_ptr as *const u8, cie_ptr + 4 - eh_frame_ptr);
    Some(EhFrameData {
        eh_frame_hdr: (base_addr + eh_frame_hdr_segment.p_vaddr) as u64
            ..(base_addr + eh_frame_hdr_segment.p_vaddr + eh_frame_hdr_segment.p_memsz) as u64,
        eh_frame: eh_frame_ptr as u64..(cie_ptr + 4) as u64,
    })
}
