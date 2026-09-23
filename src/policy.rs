//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shell / cwd / env policy primitives shared by helpers and the control plane.

use std::collections::HashSet;

/// Allowlist entry that matches any value.
pub const ALLOWLIST_WILDCARD: &str = "*";

const SHELL_METACHAR: &[char] = &[';', '|', '&', '`', '$', '>', '<', '\n', '\r'];

/// Binaries that must not appear as argv[0]; use shell.run `elevated: true` instead.
const ELEVATION_WRAPPER_BINARIES: &[&str] = &[
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/sbin/sudo",
    "/usr/bin/pkexec",
    "/bin/pkexec",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/doas",
    "/bin/doas",
    "/usr/sbin/runuser",
    "/usr/bin/runuser",
    "/usr/bin/sudoedit",
    "/bin/sudoedit",
    "/usr/bin/machinectl",
    "/bin/machinectl",
    "/usr/bin/systemd-run",
    "/bin/systemd-run",
    "sudo",
    "pkexec",
    "su",
    "doas",
    "runuser",
    "sudoedit",
    "machinectl",
    "systemd-run",
    "runas",
    "runas.exe",
];

/// Environment variables that must never be injected even with a wildcard allowlist.
pub const DANGEROUS_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "PYTHONPATH",
    "PERL5LIB",
    "RUBYLIB",
    "NODE_OPTIONS",
    "SSLKEYLOGFILE",
    "PATH",
];

/// Canonicalize argv[0] for shell policy matching.
pub fn canonicalize_binary(path: &str) -> String {
    path.trim().to_string()
}

/// Reject argv containing shell metacharacters.
pub fn validate_argv(argv: &[String]) -> Result<(), PolicyError> {
    if argv.is_empty() {
        return Err(PolicyError::EmptyArgv);
    }
    for arg in argv {
        if arg.chars().any(|c| SHELL_METACHAR.contains(&c)) {
            return Err(PolicyError::Metacharacter { arg: arg.clone() });
        }
    }
    Ok(())
}

pub fn allowlist_has_wildcard(allowed: &[String]) -> bool {
    allowed.iter().any(|entry| entry == ALLOWLIST_WILDCARD)
}

/// Reject elevation wrappers in argv[0]; privileged runs must use shell.run `elevated: true`.
pub fn check_elevation_wrapper_denied(argv: &[String]) -> Result<(), PolicyError> {
    if argv.is_empty() {
        return Ok(());
    }
    let bin = canonicalize_binary(&argv[0]).to_lowercase();
    for wrapper in ELEVATION_WRAPPER_BINARIES {
        let wrapper = wrapper.to_lowercase();
        if bin == wrapper || bin.ends_with(&format!("/{wrapper}")) {
            return Err(PolicyError::ElevationWrapperForbidden {
                binary: argv[0].clone(),
            });
        }
    }
    Ok(())
}

/// Validate elevated shell.run against elevation policy primitives.
pub fn check_elevation_policy(
    argv: &[String],
    enabled: bool,
    allowed_binaries: &[String],
) -> Result<(), PolicyError> {
    validate_argv(argv)?;
    check_elevation_wrapper_denied(argv)?;
    if !enabled {
        return Err(PolicyError::ElevationDisabled);
    }
    if allowlist_has_wildcard(allowed_binaries) {
        return Ok(());
    }
    let bin = canonicalize_binary(&argv[0]);
    let allowed_set: HashSet<_> = allowed_binaries
        .iter()
        .map(|p| canonicalize_binary(p))
        .collect();
    if allowed_set.is_empty() {
        return Err(PolicyError::ElevationDenyAll);
    }
    if !allowed_set.contains(&bin) {
        return Err(PolicyError::ElevationBinaryNotAllowed { binary: bin });
    }
    Ok(())
}

/// Check argv[0] against allowlist of canonical paths.
pub fn check_shell_policy(argv: &[String], allowed: &[String]) -> Result<(), PolicyError> {
    validate_argv(argv)?;
    check_elevation_wrapper_denied(argv)?;
    if allowlist_has_wildcard(allowed) {
        return Ok(());
    }
    let bin = canonicalize_binary(&argv[0]);
    let allowed_set: HashSet<_> = allowed.iter().map(|p| canonicalize_binary(p)).collect();
    if allowed_set.is_empty() {
        return Err(PolicyError::DenyAll);
    }
    if !allowed_set.contains(&bin) {
        return Err(PolicyError::BinaryNotAllowed { binary: bin });
    }
    Ok(())
}

/// Strip Windows verbatim/device prefixes (`\\?\C:\...`, `\\.\`, UNC) so
/// canonicalize() results still match operator allowlists.
fn strip_windows_namespace_prefix(path: &str) -> String {
    let unified = path.replace('\\', "/");
    let stripped = unified
        .strip_prefix("//?/")
        .or_else(|| unified.strip_prefix("//./"))
        .unwrap_or(&unified);
    if let Some(rest) = stripped.strip_prefix("UNC/") {
        format!("//{rest}")
    } else {
        stripped.to_string()
    }
}

pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Accept both Unix and Windows separators in allowlist checks.
    let unified = strip_windows_namespace_prefix(trimmed);
    if unified == "/" {
        return "/".to_string();
    }
    unified.trim_end_matches('/').to_string()
}

/// Reject path components that escape via `..`.
pub fn reject_path_traversal(path: &str) -> Result<(), PolicyError> {
    if path.split(['/', '\\']).any(|component| component == "..") {
        return Err(PolicyError::PathTraversal {
            path: path.to_string(),
        });
    }
    Ok(())
}

/// Lexically collapse `.` and reject unresolved `..` that escape the path.
pub fn normalize_path_no_traversal(path: &str) -> Result<String, PolicyError> {
    reject_path_traversal(path)?;
    let trimmed = path.trim();
    if trimmed == "." {
        return Ok(".".to_string());
    }
    let unified = normalize_path(path);
    let mut parts = Vec::new();
    for component in unified.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(PolicyError::PathTraversal {
                path: path.to_string(),
            });
        }
        parts.push(component);
    }
    if unified.starts_with('/') {
        Ok(format!("/{}", parts.join("/")))
    } else if looks_like_windows_path(&unified) {
        Ok(parts.join("/"))
    } else {
        Ok(parts.join("/"))
    }
}

fn looks_like_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub fn cwd_matches_allowed(cwd: &str, allowed_root: &str) -> bool {
    let Ok(cwd) = normalize_path_no_traversal(cwd) else {
        return false;
    };
    let Ok(allowed) = normalize_path_no_traversal(allowed_root) else {
        return false;
    };
    if allowed.is_empty() || cwd.is_empty() {
        return false;
    }
    if cwd == "." && allowed == "." {
        return true;
    }
    if allowed == "/" {
        return true;
    }
    let (cwd_cmp, allowed_cmp) =
        if looks_like_windows_path(&cwd) || looks_like_windows_path(&allowed) {
            (cwd.to_ascii_lowercase(), allowed.to_ascii_lowercase())
        } else {
            (cwd, allowed)
        };
    cwd_cmp == allowed_cmp || cwd_cmp.starts_with(&format!("{allowed_cmp}/"))
}

/// Check cwd against allowlist. Empty allowlist denies all paths (deny-by-default).
/// Subdirectories of an allowed root are permitted. Wildcard `*` allows any cwd.
pub fn check_cwd_policy(cwd: &str, allowed: &[String]) -> Result<(), PolicyError> {
    reject_path_traversal(cwd)?;
    if allowlist_has_wildcard(allowed) {
        return Ok(());
    }
    if allowed.is_empty() {
        return Err(PolicyError::CwdNotAllowed {
            cwd: normalize_path(cwd),
        });
    }
    let cwd = normalize_path_no_traversal(cwd)?;
    if allowed
        .iter()
        .any(|root| cwd_matches_allowed(&cwd, root))
    {
        Ok(())
    } else {
        Err(PolicyError::CwdNotAllowed { cwd })
    }
}

/// Check env keys against allowlist. Empty allowlist denies all keys (deny-by-default).
/// Wildcard `*` allows any key except [`DANGEROUS_ENV_KEYS`].
pub fn check_env_policy(
    env: &std::collections::HashMap<String, String>,
    allowed: &[String],
) -> Result<(), PolicyError> {
    let wildcard = allowlist_has_wildcard(allowed);
    let allowed_set: HashSet<_> = allowed
        .iter()
        .filter(|entry| *entry != ALLOWLIST_WILDCARD)
        .cloned()
        .collect();
    for key in env.keys() {
        let upper = key.to_ascii_uppercase();
        if DANGEROUS_ENV_KEYS.iter().any(|blocked| *blocked == upper) {
            return Err(PolicyError::DangerousEnv { key: key.clone() });
        }
        if wildcard {
            continue;
        }
        if allowed_set.is_empty() || !allowed_set.contains(key) {
            return Err(PolicyError::EnvNotAllowed { key: key.clone() });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("argv must not be empty")]
    EmptyArgv,
    #[error("shell metacharacter in argument: {arg}")]
    Metacharacter { arg: String },
    #[error("shell policy deny-all")]
    DenyAll,
    #[error("binary not allowed: {binary}")]
    BinaryNotAllowed { binary: String },
    #[error("working directory not allowed: {cwd}")]
    CwdNotAllowed { cwd: String },
    #[error("path traversal rejected: {path}")]
    PathTraversal { path: String },
    #[error("environment variable not allowed: {key}")]
    EnvNotAllowed { key: String },
    #[error("dangerous environment variable blocked: {key}")]
    DangerousEnv { key: String },
    #[error("elevation wrapper forbidden in argv: {binary}; use elevated=true instead")]
    ElevationWrapperForbidden { binary: String },
    #[error("elevated execution is disabled for this identity")]
    ElevationDisabled,
    #[error("elevation policy deny-all")]
    ElevationDenyAll,
    #[error("binary not allowed for elevated execution: {binary}")]
    ElevationBinaryNotAllowed { binary: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_metacharacters() {
        let err = validate_argv(&["/bin/ls".into(), "-la; rm".into()]).unwrap_err();
        assert!(matches!(err, PolicyError::Metacharacter { .. }));
    }

    #[test]
    fn allows_clean_argv() {
        validate_argv(&["/usr/bin/uptime".into()]).unwrap();
    }

    #[test]
    fn shell_policy_enforced() {
        let allowed = vec!["/usr/bin/uptime".into()];
        check_shell_policy(&["/usr/bin/uptime".into()], &allowed).unwrap();
        check_shell_policy(&["/bin/sh".into()], &allowed).unwrap_err();
    }

    #[test]
    fn rejects_extended_elevation_wrappers() {
        for wrapper in ["su", "doas", "runuser", "sudoedit", "machinectl", "systemd-run"] {
            check_elevation_wrapper_denied(&[wrapper.into()]).unwrap_err();
        }
        check_elevation_wrapper_denied(&["/usr/bin/doas".into()]).unwrap_err();
        check_elevation_wrapper_denied(&["/usr/bin/uptime".into()]).unwrap();
    }

    #[test]
    fn shell_policy_wildcard_allows_any_binary() {
        let allowed = vec![ALLOWLIST_WILDCARD.into()];
        check_shell_policy(&["/bin/sh".into(), "-c".into(), "id".into()], &allowed).unwrap();
    }

    #[test]
    fn cwd_allows_subdirectories() {
        let allowed = vec!["/tmp".into()];
        check_cwd_policy("/tmp", &allowed).unwrap();
        check_cwd_policy("/tmp/nested", &allowed).unwrap();
        check_cwd_policy("/tmp/nested/deep", &allowed).unwrap();
        check_cwd_policy("/etc", &allowed).unwrap_err();
    }

    #[test]
    fn cwd_empty_allowlist_denies_all_paths() {
        check_cwd_policy("/any/path", &[]).unwrap_err();
    }

    #[test]
    fn rejects_path_traversal_components() {
        let allowed = vec!["/tmp".into()];
        check_cwd_policy("/tmp/../etc/passwd", &allowed).unwrap_err();
        assert!(matches!(
            reject_path_traversal("/tmp/../etc"),
            Err(PolicyError::PathTraversal { .. })
        ));
    }

    #[test]
    fn cwd_windows_paths_normalize_separators() {
        let allowed = vec![r"C:\Windows\Temp".into()];
        check_cwd_policy(r"C:\Windows\Temp", &allowed).unwrap();
        check_cwd_policy(r"C:\Windows\Temp\nested", &allowed).unwrap();
        check_cwd_policy("C:/Windows/Temp/nested", &allowed).unwrap();
        check_cwd_policy(r"C:\Windows\System32", &allowed).unwrap_err();
    }

    #[test]
    fn cwd_windows_paths_are_case_insensitive() {
        let allowed = vec!["C:/Windows/Temp".into()];
        check_cwd_policy(r"c:\windows\temp\file.txt", &allowed).unwrap();
    }

    #[test]
    fn cwd_windows_verbatim_prefix_matches_allowlist() {
        let allowed = vec![r"C:\Windows\Temp".into()];
        check_cwd_policy(r"\\?\C:\Windows\Temp\nested", &allowed).unwrap();
        check_cwd_policy("//?/C:/Windows/Temp/nested", &allowed).unwrap();
    }

    #[test]
    fn path_blocked_even_with_wildcard() {
        let mut env = std::collections::HashMap::new();
        env.insert("PATH".into(), "/evil".into());
        let err = check_env_policy(&env, &[ALLOWLIST_WILDCARD.into()]).unwrap_err();
        assert!(matches!(err, PolicyError::DangerousEnv { .. }));
    }
}
