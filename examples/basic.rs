use framehop::{MustNotAllocateDuringUnwind, Unwinder, UnwinderNative};

fn main() {
    let objects = runwind::find_objects();
    let mut unwinder: UnwinderNative<_, MustNotAllocateDuringUnwind> = UnwinderNative::new();
    for obj in &objects {
        unwinder.add_module(obj.to_module());
    }
}
