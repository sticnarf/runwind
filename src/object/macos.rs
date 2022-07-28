use std::mem::ManuallyDrop;

use memmap2::Mmap;
use once_cell::sync::Lazy;

use super::Object;

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
    None
}

pub struct ObjectMmap {
    pub mmap: ManuallyDrop<Mmap>,
    pub obj_file: ManuallyDrop<object::File<'static, &'static [u8]>>,
}
