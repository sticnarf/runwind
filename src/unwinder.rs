use std::{arch::asm, num::NonZeroU64};

use framehop::{
    AllocationPolicy, CacheNative, Error, FrameAddress, UnwindRegsNative, Unwinder as _,
    UnwinderNative,
};

pub struct Unwinder<P>
where
    P: AllocationPolicy<&'static [u8]>,
{
    unwinder: UnwinderNative<&'static [u8], P>,
}

impl<P> Unwinder<P>
where
    P: AllocationPolicy<&'static [u8]>,
{
    pub fn new() -> Self {
        let mut unwinder = UnwinderNative::new();
        for obj in crate::get_objects() {
            unwinder.add_module(obj.to_module());
        }
        Unwinder { unwinder }
    }

    pub fn iter_frames<'u, 'c>(
        &'u self,
        cache: &'c mut CacheNative<&'static [u8], P>,
    ) -> UnwindIterator<'u, 'c, P> {
        let (ip, sp, bp): (u64, u64, u64);
        unsafe {
            asm!(
                "lea {ip}, [rip]",
                "mov {sp}, rsp",
                "mov {bp}, rbp",
                ip = out(reg) ip,
                sp = out(reg) sp,
                bp = out(reg) bp,
            );
        }
        let regs = UnwindRegsNative::new(ip, sp, bp);
        UnwindIterator {
            unwinder: &self.unwinder,
            cache,
            regs,
            addr: FrameAddress::InstructionPointer(ip),
        }
    }

    pub fn iter_frames_with_regs<'u, 'c>(
        &'u self,
        regs: UnwindRegsNative,
        cache: &'c mut CacheNative<&'static [u8], P>,
    ) -> UnwindIterator<'u, 'c, P> {
        let ip = regs.ip();
        UnwindIterator {
            unwinder: &self.unwinder,
            cache,
            regs,
            addr: FrameAddress::InstructionPointer(ip),
        }
    }
}

impl<P> Default for Unwinder<P>
where
    P: AllocationPolicy<&'static [u8]>,
{
    fn default() -> Self {
        Self::new()
    }
}

pub struct UnwindIterator<'u, 'c, P>
where
    P: AllocationPolicy<&'static [u8]>,
{
    unwinder: &'u UnwinderNative<&'static [u8], P>,
    cache: &'c mut CacheNative<&'static [u8], P>,
    regs: UnwindRegsNative,
    addr: FrameAddress,
}

impl<'u, 'c, P> UnwindIterator<'u, 'c, P>
where
    P: AllocationPolicy<&'static [u8]>,
{
    pub fn try_next(&mut self) -> Result<Option<usize>, Error> {
        if let Some(new_addr) = self
            .unwinder
            .unwind_frame(self.addr, &mut self.regs, self.cache, &mut read_stack)?
            .and_then(NonZeroU64::new)
        {
            self.addr = FrameAddress::ReturnAddress(new_addr);
            Ok(Some(new_addr.get() as usize))
        } else {
            Ok(None)
        }
    }
}

fn read_stack(addr: u64) -> Result<u64, ()> {
    let aligned_addr = addr & !0b111;
    if crate::addr_validate::validate(aligned_addr as _) {
        Ok(unsafe { (aligned_addr as *const u64).read() })
    } else {
        Err(())
    }
}
