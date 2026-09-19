//! Size-based chunking strategy.
//!
//! Files are split into fixed-size chunks for transfer and dedup. The chunk
//! size depends on the file size, following Syncthing's thresholds:
//!
//! | File size    | Chunk size |
//! |--------------|------------|
//! | <= 128 KiB   | 0 (no chunking) |
//! | <= 256 MiB   | 128 KiB    |
//! | <= 1 GiB     | 1 MiB      |
//! | <= 16 GiB    | 4 MiB      |
//! | > 16 GiB     | 16 MiB     |
//!
//! See `chunking-strategy-reference.md` in the desktop project for the
//! analysis behind these thresholds.

use crate::invariants::chunk_sizes::{self, *};

/// Compute the chunk size in bytes for a file of `file_size` bytes.
///
/// Returns 0 for files small enough to be transferred without chunking.
///
/// # Examples
///
/// ```
/// use kfilesync_core::service::chunking::compute_chunk_size;
/// assert_eq!(compute_chunk_size(0), 0);
/// assert_eq!(compute_chunk_size(100_000), 0);                // < 128 KiB
/// assert_eq!(compute_chunk_size(200_000), 128 * 1024);       // 128 KiB chunks
/// assert_eq!(compute_chunk_size(500 * 1024 * 1024), 1024 * 1024); // 1 MiB chunks
/// ```
#[must_use]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub const fn compute_chunk_size(file_size: u64) -> u32 {
    if file_size <= chunk_sizes::UNCHUNKED_MAX {
        0
    } else if file_size <= chunk_sizes::SMALL_MAX {
        CHUNK_128_KIB
    } else if file_size <= chunk_sizes::MEDIUM_MAX {
        CHUNK_1_MIB
    } else if file_size <= chunk_sizes::LARGE_MAX {
        CHUNK_4_MIB
    } else {
        CHUNK_16_MIB
    }
}

/// Number of chunks a file of `file_size` would be split into with the
/// computed chunk size.
///
/// Returns 0 when the file is unchunked.
#[must_use]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub const fn compute_chunk_count(file_size: u64) -> u32 {
    let chunk_size: u32 = compute_chunk_size(file_size);
    if chunk_size == 0 {
        return 0;
    }
    // Ceiling division for the last (possibly smaller) chunk.
    let chunks: u64 = file_size.div_ceil(chunk_size as u64);
    // Safe because chunk_count cannot exceed `u32::MAX` given our thresholds:
    // max file = `u64::MAX`, min chunk = 128 KiB -> <= 2^47 chunks.
    // For our largest configured chunk (16 MiB) with `u64::MAX`, the count
    // fits in u32 only if we cap; for safety we saturate.
    if chunks > u32::MAX as u64 {
        u32::MAX
    } else {
        chunks as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_match_spec() {
        // Boundary cases.
        assert_eq!(compute_chunk_size(0), 0);
        assert_eq!(compute_chunk_size(131_072), 0); // exactly 128 KiB -> no chunking
        assert_eq!(compute_chunk_size(131_073), CHUNK_128_KIB);
        assert_eq!(compute_chunk_size(268_435_456), CHUNK_128_KIB); // exactly 256 MiB
        assert_eq!(compute_chunk_size(268_435_457), CHUNK_1_MIB);
        assert_eq!(compute_chunk_size(1_073_741_824), CHUNK_1_MIB); // 1 GiB
        assert_eq!(compute_chunk_size(1_073_741_825), CHUNK_4_MIB);
        assert_eq!(compute_chunk_size(17_179_869_184), CHUNK_4_MIB); // 16 GiB
        assert_eq!(compute_chunk_size(17_179_869_185), CHUNK_16_MIB);
    }

    #[test]
    fn chunk_count_basic() {
        assert_eq!(compute_chunk_count(0), 0);
        assert_eq!(compute_chunk_count(100_000), 0);
        assert_eq!(compute_chunk_count(131_072 + 1), 2); // just over 128 KiB -> 2 chunks
        assert_eq!(compute_chunk_count(CHUNK_128_KIB as u64), 0); // <= 128 KiB is unchunked
        assert_eq!(compute_chunk_count(CHUNK_128_KIB as u64 * 2), 2);
        assert_eq!(compute_chunk_count(CHUNK_128_KIB as u64 * 3), 3);
    }

    #[test]
    fn const_fn_usable_at_compile_time() {
        const SIZE: u32 = compute_chunk_size(500 * 1024 * 1024);
        assert_eq!(SIZE, CHUNK_1_MIB);
    }
}
