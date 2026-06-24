//! Curated per-ecosystem exclude sets. These are *convenience defaults* layered
//! onto the user's `--exclude` list — purely additive, never overriding an
//! explicit include. A profile resolves to bare directory names and globs that
//! `build_globset` already knows how to expand (a bare `node_modules` becomes
//! `node_modules`, `node_modules/**`, `**/node_modules/**`), so the lists here
//! stay readable.
//!
//! Scope discipline: these target *build artifacts, dependency trees, caches,
//! and lockfiles* — high-token, low-signal noise a model rarely needs. They do
//! NOT exclude source, config, or anything ambiguous. When unsure, leave it in;
//! a user can always add their own `--exclude`, but a default that drops real
//! code is a silent footgun.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "lowercase"))]
pub enum LanguageProfile {
    Python,
    Node,
    Rust,
    Go,
    Java,
}

impl LanguageProfile {
    /// Exclude patterns for this ecosystem. Bare names rely on build_globset's
    /// gitignore-style subtree expansion; explicit globs are used where a
    /// pattern (not a dir) is meant.
    pub fn exclude_globs(self) -> &'static [&'static str] {
        match self {
            LanguageProfile::Python => &[
                "__pycache__", // bytecode cache dir, any depth
                "*.pyc",
                "*.pyo",
                ".venv",
                "venv",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                "*.egg-info",
                ".tox",
                "build", // setuptools/pep517 build dir
                "dist",  // wheels/sdists
            ],
            LanguageProfile::Node => &[
                "node_modules",
                "dist",
                "build",
                ".next", // Next.js
                ".nuxt",
                ".turbo",
                "coverage",
                "*.tsbuildinfo",
                ".parcel-cache",
                // Note: NOT excluding package-lock.json / yarn.lock by default —
                // see the lockfile note below.
            ],
            LanguageProfile::Rust => &[
                "target",     // the big one; cargo build output
                "Cargo.lock", // see lockfile note — debatable, included here
            ],
            LanguageProfile::Go => &[
                "vendor", // vendored deps (only present if `go mod vendor`)
                "bin",
                // Go build output usually isn't a fixed dir; binaries vary by name,
                // so there's little safe-to-exclude beyond vendor/ and bin/.
            ],
            LanguageProfile::Java => &[
                "target", // Maven
                "build",  // Gradle
                ".gradle", "*.class", "*.jar", // debatable for source repos; see note
            ],
        }
    }
}

/// Flatten one or more profiles into an owned exclude list, ready to append to
/// `config.exclude_patterns`. De-duplicated so overlapping profiles (Node+Java
/// both wanting `build`) don't add it twice.
pub fn profile_excludes(profiles: &[LanguageProfile]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in profiles {
        for g in p.exclude_globs() {
            let s = (*g).to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{build_globset, should_include_file};
    use std::path::Path;

    #[test]
    fn python_profile_excludes_pycache_and_keeps_source() {
        let globs = profile_excludes(&[LanguageProfile::Python]);
        let exclude = build_globset(&globs);
        let include = build_globset(&[]);

        for p in [
            "__pycache__/foo.pyc",
            "src/__pycache__/x.pyc",
            "app/module.pyc",
            ".venv/lib/x.py",
        ] {
            assert!(
                !should_include_file(Path::new(p), &include, &exclude),
                "{p} should be excluded"
            );
        }
        for p in ["src/main.py", "app/views.py", "setup.py"] {
            assert!(
                should_include_file(Path::new(p), &include, &exclude),
                "{p} should be kept"
            );
        }
    }

    #[test]
    fn profiles_dedup_overlapping_globs() {
        let combined = profile_excludes(&[LanguageProfile::Node, LanguageProfile::Java]);
        let build_count = combined.iter().filter(|g| g.as_str() == "build").count();
        assert_eq!(build_count, 1, "overlapping `build` should appear once");
    }
}
