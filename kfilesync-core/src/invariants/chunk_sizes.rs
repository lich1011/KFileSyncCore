//! Size thresholds and chunk-size constants for [`crate::service::chunking`].

/// Files at or below this size are transferred without chunking.
pub const UNCHUNKED_MAX: u64 = 128 * 1024; // 128 KiB

/// Upper bound for the 128 KiB-chunk tier.
pub const SMALL_MAX: u64 = 256 * 1024 * 1024; // 256 MiB

/// Upper bound for the 1 MiB-chunk tier.
pub const MEDIUM_MAX: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Upper bound for the 4 MiB-chunk tier.
pub const LARGE_MAX: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB

/// 128 KiB chunk size used for small files.
pub const CHUNK_128_KIB: u32 = 128 * 1024;

/// 1 MiB chunk size used for medium files.
pub const CHUNK_1_MIB: u32 = 1024 * 1024;

/// 4 MiB chunk size used for large files.
pub const CHUNK_4_MIB: u32 = 4 * 1024 * 1024;

/// 16 MiB chunk size used for huge files.
pub const CHUNK_16_MIB: u32 = 16 * 1024 * 1024;
