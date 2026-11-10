// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! A global allocator that counts the bytes live on the heap, for NFR-2.
//!
//! This is the one place in the workspace with unsafe code. A global
//! allocator cannot be written without it, and resident memory (what the
//! benchmark measured before) is too coarse to see one request. It wraps
//! the system allocator and only adds to and subtracts from a counter.
//! The crate is never published; every published crate forbids unsafe
//! code, and `scripts/unsafe-boundary.sh` fails CI if unsafe code
//! appears anywhere but here.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting.
pub(crate) struct Counting;

// SAFETY: each method forwards its arguments to `System`, whose contract
// is the one `GlobalAlloc` states, and returns what it returned. The
// counter never affects an allocation.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc`, passed on unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator with `layout`, as the
        // caller guarantees, and so from `System`.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as for `dealloc`, and `new_size` meets the caller's
        // contract for `realloc`.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        moved
    }
}

/// The bytes this process has allocated and not yet freed.
pub(crate) fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}
