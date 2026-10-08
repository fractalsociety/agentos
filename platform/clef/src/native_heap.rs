//! Allocator for the PD's exclusive, root-provisioned 1 GiB arena.
//! Fixed metadata, bounded first-fit scan, no OS calls. Allocation failure is
//! reported by the panic boundary. Only one inference call is allowed per boot.
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
const UNIT: usize = 32768;
const UNITS: usize = 32768;
struct State {
    base: *mut u8,
    lengths: [u32; UNITS],
}
struct Heap {
    lock: AtomicBool,
    initialized: AtomicBool,
    state: UnsafeCell<State>,
}
// All metadata access is serialized; root gives the arena only to this PD.
unsafe impl Sync for Heap {}
#[cfg_attr(not(feature = "host"), global_allocator)]
static HEAP: Heap = Heap {
    lock: AtomicBool::new(false),
    initialized: AtomicBool::new(false),
    state: UnsafeCell::new(State {
        base: ptr::null_mut(),
        lengths: [0; UNITS],
    }),
};
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        HEAP.lock.store(false, Ordering::Release);
    }
}
fn lock() -> Guard {
    while HEAP
        .lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    Guard
}
/// Safety: region is exclusive writable RAM and remains mapped for the PD life.
pub unsafe fn init(base: *mut u8, bytes: usize) -> bool {
    let _guard = lock();
    if base.is_null()
        || base as usize % UNIT != 0
        || bytes != UNIT * UNITS
        || HEAP.initialized.load(Ordering::Relaxed)
    {
        return false;
    }
    (*HEAP.state.get()).base = base;
    HEAP.initialized.store(true, Ordering::Release);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arena_reclaims_and_rejects_exhaustion() {
        // Only the metadata and first two pages are touched; the large backing
        // allocation uses the same virtual bounds as the native mapped arena.
        unsafe {
            let backing = Layout::from_size_align(UNIT * UNITS, UNIT).unwrap();
            let base = std::alloc::System.alloc(backing);
            assert!(!base.is_null());
            assert!(!init(base, 1));
            assert!(init(base, UNIT * UNITS));
            assert!(!init(base, UNIT * UNITS));
            let small = Layout::from_size_align(17, 16).unwrap();
            let a = HEAP.alloc(small);
            let b = HEAP.alloc(small);
            assert_eq!(a, base);
            assert_eq!(b, base.add(UNIT));
            a.write(91);
            b.write(42);
            assert_eq!(a.read(), 91);
            assert_eq!(b.read(), 42);
            assert!(HEAP.alloc(backing).is_null());
            HEAP.dealloc(a, small);
            HEAP.dealloc(b, small);
            let all = HEAP.alloc(backing);
            assert_eq!(all, base);
            assert!(HEAP.alloc(small).is_null());
            HEAP.dealloc(all, backing);
            std::alloc::System.dealloc(base, backing);
        }
    }
}
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.initialized.load(Ordering::Acquire) || layout.align() > UNIT {
            return ptr::null_mut();
        }
        let Some(bytes) = layout.size().checked_add(UNIT - 1) else {
            return ptr::null_mut();
        };
        let needed = (bytes / UNIT).max(1);
        if needed > UNITS {
            return ptr::null_mut();
        }
        let _guard = lock();
        let s = &mut *self.state.get();
        let mut free = 0;
        for i in 0..UNITS {
            if s.lengths[i] == 0 {
                free += 1;
            } else {
                free = 0;
            }
            if free == needed {
                let start = i + 1 - needed;
                s.lengths[start] = needed as u32;
                s.lengths[start + 1..=i].fill(u32::MAX);
                return s.base.add(start * UNIT);
            }
        }
        ptr::null_mut()
    }
    unsafe fn dealloc(&self, p: *mut u8, _layout: Layout) {
        let _guard = lock();
        let s = &mut *self.state.get();
        let Some(offset) = (p as usize).checked_sub(s.base as usize) else {
            return;
        };
        if offset % UNIT != 0 || offset >= UNIT * UNITS {
            return;
        }
        let start = offset / UNIT;
        let n = s.lengths[start] as usize;
        if n == 0 || n > UNITS - start {
            return;
        }
        s.lengths[start..start + n].fill(0);
    }
}
