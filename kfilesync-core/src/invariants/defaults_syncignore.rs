//! Default `.syncignore` rules, shared by desktop and mobile.
//!
//! [`COMMON_DEFAULTS`] is always applied. [`MOBILE_DEFAULTS`] is only applied
//! when the host is a mobile device (Android / iOS) - desktops do not need
//! to ignore build artifacts of mobile dev environments.
//!
//! Both lists follow gitignore syntax.

/// Defaults applied on every platform.
///
/// **Note**: `.lansync-tmp/` MUST be in this list. It is the directory the
/// core uses for atomic file replacement. Failing to ignore it causes
/// pull/push thrashing - see `CROSS_VALIDATION_DESKTOP_MOBILE.md` §3.6.
pub const COMMON_DEFAULTS: &[&str] = &[
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "$RECYCLE.BIN",
    ".lansync-tmp/",
    ".Trashes",
    "Trash-*",
];

/// Defaults applied additionally on mobile hosts.
///
/// These cover artifacts from typical mobile / desktop IDE workflows that
/// users do not want to sync.
pub const MOBILE_DEFAULTS: &[&str] = &[
    // iOS build artifacts
    "*.ipa",
    "*.dSYM",
    "*.xcarchive",
    "*.xcuserstate",
    "DerivedData/",
    // Android build artifacts
    "*.apk",
    "*.aab",
    "build/",
    ".gradle/",
    ".cxx/",
    // IDE caches
    ".idea/",
    ".vscode/",
    ".cursor/",
    "*.iml",
    // Common temp / lock files
    "*.tmp",
    "*.part",
    "*.crdownload",
    "~*$*",
    ".~lock.*#*",
    "*.swp",
    "*.swo",
    // Misc
    "node_modules/",
    ".thumbnails/",
    ".Trash/",
];
