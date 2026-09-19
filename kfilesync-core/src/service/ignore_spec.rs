//! `.syncignore` matching, gitignore-compatible.
//!
//! Wraps the `ignore` crate's `Gitignore` parser. The walker functionality
//! is disabled because core does no I/O - hosts perform directory traversal
//! and ask this module whether each entry should be skipped.
//!
//! # Sprint 6 implementation
//!
//! Uses `Gitignore::matched_path_or_any_parents` (not the plain `matched`)
//! - this is the one call that gets gitignore's parent-directory
//!   short-circuit semantics right: if `build/` is ignored, then
//!   `build/output.txt` is ignored too, even though no single rule matches
//!   `build/output.txt` directly. `CROSS_VALIDATION_DESKTOP_MOBILE.md` §3.6
//!   found mobile's hand-rolled glob-regex implementation got exactly this
//!   wrong (its own comment admitted "can't un-ignore already-ignored by
//!   parent directory" was unimplemented) - delegating entirely to the
//!   `ignore` crate's own traversal-aware matcher removes the class of bug,
//!   not just this one instance of it.

use alloc::string::{String, ToString};

use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::invariants::defaults_syncignore::{COMMON_DEFAULTS, MOBILE_DEFAULTS};

/// Errors when building an [`IgnoreSpec`].
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(uniffi::Error))]
pub enum IgnoreSpecError {
    /// One of the rules (a default, `.syncignore` line, or user rule)
    /// failed to parse as a gitignore pattern.
    #[error("invalid rule: {0}")]
    InvalidRule(String),
}

/// Compiled `.syncignore` matcher.
#[cfg_attr(feature = "ffi", derive(uniffi::Object))]
pub struct IgnoreSpec {
    inner: Gitignore,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
impl IgnoreSpec {
    /// Build a matcher for `share_root`, combining built-in defaults with
    /// any `.syncignore` content and additional user rules, in this
    /// precedence order (later entries can override earlier ones, per
    /// standard gitignore negation-rule semantics - e.g. a later `!foo`
    /// un-ignores an earlier `foo`):
    ///
    /// 1. [`COMMON_DEFAULTS`] (always)
    /// 2. [`MOBILE_DEFAULTS`] (only if `is_mobile`)
    /// 3. `.syncignore_content`, parsed line-by-line exactly like a real
    ///    `.gitignore` file - comments (`#`) and blank lines are already
    ///    handled correctly by the underlying parser, not re-implemented
    ///    here.
    /// 4. `extra_user_rules` (e.g. from app settings, applied last so they
    ///    can override both the defaults and `.syncignore`)
    ///
    /// `share_root` is accepted for API stability and potential future use
    /// (e.g. nested per-directory `.gitignore` layering) but currently has
    /// no effect on matching - see the implementation note on why using a
    /// fixed internal root is strictly safer, not a loss of behavior.
    ///
    /// # Errors
    ///
    /// Returns [`IgnoreSpecError::InvalidRule`] if any rule (built-in,
    /// `.syncignore`, or user-supplied) fails to parse. A malformed
    /// built-in default would indicate a bug in this crate, not the host;
    /// a malformed `.syncignore` or user rule indicates the host should
    /// surface a validation error rather than silently drop the rule.
    #[cfg_attr(feature = "ffi", uniffi::constructor)]
    pub fn build(
        share_root: &str,
        syncignore_content: Option<String>,
        extra_user_rules: &[String],
        is_mobile: bool,
    ) -> Result<Self, IgnoreSpecError> {
        // Deliberately NOT `GitignoreBuilder::new(share_root)`: the
        // underlying matcher panics ("path is expected to be under the
        // root") if a path passed to `is_ignored` doesn't share a literal
        // prefix with whatever root the builder was built with. Since core
        // does no real filesystem I/O, `share_root`'s concrete value has no
        // meaningful effect on matching anyway (verified: root="/" behaves
        // identically to any other root string for the relative paths this
        // API is documented to accept) - using the same fixed root always
        // removes an entire class of panic on host input that merely
        // *looks* absolute (a leading `/`), without changing behavior for
        // any input that follows the documented (relative-path) contract.
        let _ = share_root;
        let mut builder = GitignoreBuilder::new("/");

        let mut add = |line: &str| -> Result<(), IgnoreSpecError> {
            builder
                .add_line(None, line)
                .map_err(|e| IgnoreSpecError::InvalidRule(e.to_string()))?;
            Ok(())
        };

        for rule in COMMON_DEFAULTS {
            add(rule)?;
        }
        if is_mobile {
            for rule in MOBILE_DEFAULTS {
                add(rule)?;
            }
        }
        if let Some(content) = syncignore_content {
            for line in content.lines() {
                add(line)?;
            }
        }
        for rule in extra_user_rules {
            add(rule)?;
        }

        let inner = builder
            .build()
            .map_err(|e| IgnoreSpecError::InvalidRule(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Is `path` (relative to share root, `/`-separated, matching
    /// `domain::FileEntry::path`'s convention) ignored?
    ///
    /// Checks `path` itself *and* every parent directory up to the share
    /// root - see the module docs for why this matters.
    ///
    /// Tolerates an accidental leading `/` (stripped before matching)
    /// rather than panicking on it - `domain::FileEntry::path` never has
    /// one, but this function stays defensive against a host that sends
    /// one anyway rather than crashing a sync pass over it.
    #[must_use]
    pub fn is_ignored(&self, path: &str, is_directory: bool) -> bool {
        let path = path.strip_prefix('/').unwrap_or(path);
        self.inner
            .matched_path_or_any_parents(path, is_directory)
            .is_ignore()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_defaults_are_always_applied() {
        let spec = IgnoreSpec::build("/share", None, &[], false).unwrap();
        assert!(spec.is_ignored(".DS_Store", false));
        assert!(spec.is_ignored("nested/dir/.DS_Store", false));
        assert!(spec.is_ignored("Thumbs.db", false));
    }

    #[test]
    fn lansync_tmp_is_always_ignored_the_cross_validation_regression() {
        // CROSS_VALIDATION_DESKTOP_MOBILE.md §3.6's key finding: mobile's
        // hand-rolled defaults list was missing this entry. Pinned here so
        // a future edit to invariants::defaults_syncignore can't drop it
        // silently.
        let desktop_spec = IgnoreSpec::build("/share", None, &[], false).unwrap();
        let mobile_spec = IgnoreSpec::build("/share", None, &[], true).unwrap();
        assert!(desktop_spec.is_ignored(".lansync-tmp", true));
        assert!(mobile_spec.is_ignored(".lansync-tmp", true));
        assert!(mobile_spec.is_ignored(".lansync-tmp/partial_download.bin", false));
    }

    #[test]
    fn mobile_defaults_only_apply_when_is_mobile_is_true() {
        let desktop_spec = IgnoreSpec::build("/share", None, &[], false).unwrap();
        let mobile_spec = IgnoreSpec::build("/share", None, &[], true).unwrap();
        assert!(!desktop_spec.is_ignored("build", true));
        assert!(mobile_spec.is_ignored("build", true));
    }

    #[test]
    fn parent_directory_short_circuit_ignores_everything_beneath_an_ignored_dir() {
        // This is the exact semantic CROSS_VALIDATION flagged as broken in
        // mobile's hand-rolled matcher: a file with no rule of its own
        // still counts as ignored if an ancestor directory does.
        let spec = IgnoreSpec::build("/share", None, &["build/".to_string()], false).unwrap();
        assert!(spec.is_ignored("build", true));
        assert!(spec.is_ignored("build/output.txt", false));
        assert!(spec.is_ignored("build/nested/deep/file.o", false));
        assert!(!spec.is_ignored("src/main.rs", false));
    }

    #[test]
    fn syncignore_content_is_parsed_like_a_real_gitignore_file() {
        let content = "# a comment, and a blank line follow\n\n*.log\ncache/\n";
        let spec = IgnoreSpec::build("/share", Some(content.to_string()), &[], false).unwrap();
        assert!(spec.is_ignored("debug.log", false));
        assert!(spec.is_ignored("cache/entry.bin", false));
        assert!(!spec.is_ignored("keep.txt", false));
    }

    #[test]
    fn extra_user_rules_apply_after_syncignore_and_can_negate_it() {
        let content = "*.log\n";
        let spec = IgnoreSpec::build("/share", Some(content.to_string()), &["!important.log".to_string()], false).unwrap();
        assert!(spec.is_ignored("debug.log", false));
        assert!(!spec.is_ignored("important.log", false));
    }

    #[test]
    fn double_star_glob_patterns_work() {
        let spec = IgnoreSpec::build("/share", None, &["**/*.bak".to_string(), "temp/**".to_string()], false).unwrap();
        assert!(spec.is_ignored("a/b/c/file.bak", false));
        assert!(spec.is_ignored("temp/x/y/z.txt", false));
        assert!(!spec.is_ignored("keep.bak.txt", false));
    }

    #[test]
    fn an_invalid_rule_is_reported_as_a_build_error() {
        // An invalid range like `[z-a]` fails glob compilation.
        let result = IgnoreSpec::build("/share", None, &["a\\".to_string()], false);
        assert!(result.is_err());
    }

    #[test]
    fn is_ignored_works_the_same_regardless_of_a_leading_slash_in_the_path() {
        let spec = IgnoreSpec::build("/share", None, &[".DS_Store".to_string()], false).unwrap();
        assert!(spec.is_ignored(".DS_Store", false));
        assert!(spec.is_ignored("/.DS_Store", false));
    }
}
