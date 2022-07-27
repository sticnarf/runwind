use std::{
    fmt::{self, Debug},
    fs::File,
    mem::ManuallyDrop,
    ops::Range,
    path::{Path, PathBuf},
    slice,
};

use framehop::{Module, ModuleSvmaInfo, ModuleUnwindData, TextByteData};
use libc::c_void;
use log::warn;
use memmap2::Mmap;
use object::{Object as _, ObjectSection};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub use dl_iterate_phdr::get_objects;
#[cfg(any(target_os = "macos"))]
pub use macos::get_objects;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod dl_iterate_phdr;
#[cfg(any(target_os = "macos"))]
mod macos;

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
        let base_avma = self.phdr.base_addr as u64;
        let text_range = (self.phdr.base_addr + self.phdr.text.p_vaddr) as u64
            ..(self.phdr.base_addr + self.phdr.text.p_vaddr + self.phdr.text.p_memsz) as u64;

        let eh_frame_hdr = self.section_range(".eh_frame_hdr");
        let eh_frame = self.section_range(".eh_frame");
        let unwind_data = match (&eh_frame_hdr, &eh_frame) {
            (Some(eh_frame_hdr), Some(eh_frame)) => ModuleUnwindData::EhFrameHdrAndEhFrame(
                self.range_data(eh_frame_hdr),
                self.range_data(eh_frame),
            ),
            (None, Some(eh_frame)) => ModuleUnwindData::EhFrame(self.range_data(eh_frame)),
            _ => ModuleUnwindData::None,
        };

        let text_bytes = unsafe {
            slice::from_raw_parts(
                (self.phdr.base_addr + self.phdr.text.p_vaddr) as *const u8,
                self.phdr.text.p_memsz,
            )
        };
        let text_data = TextByteData::new(text_bytes, text_range.clone());

        Module::new(
            name,
            text_range,
            base_avma,
            ModuleSvmaInfo {
                // FIXME: should be the vmaddr of the __TEXT segment for mach-O
                base_svma: 0,
                text: self.section_range(".text"),
                text_env: None,
                stubs: None,
                stub_helper: None,
                eh_frame,
                eh_frame_hdr,
                got: self.section_range(".got"),
            },
            unwind_data,
            Some(text_data),
        )
    }

    pub fn obj_file(&self) -> &'_ object::File<'static, &'static [u8]> {
        &*self.mmap.obj_file
    }

    pub fn base_addr(&self) -> usize {
        self.phdr.base_addr
    }

    pub fn text_svma(&self) -> Range<usize> {
        self.phdr.text.p_vaddr..(self.phdr.text.p_vaddr + self.phdr.text.p_memsz)
    }
}

impl Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Object").field("phdr", &self.phdr).finish()
    }
}
