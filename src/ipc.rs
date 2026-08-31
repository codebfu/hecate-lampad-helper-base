//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared IPC wire protocol between hecate-lampad agents and helpers.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

/// Shared Unix group for agent ↔ helper IPC sockets and runtime directory.
pub const IPC_GROUP_NAME: &str = "hecate-ipc";

/// Default Unix socket / named-pipe path for the desktop helper.
pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/hecate-lampad/desktop.sock")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/hecate-lampad/desktop.sock")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"\\.\pipe\hecate-lampad-desktop")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/tmp/hecate-lampad-desktop.sock")
    }
}

pub fn helper_binary_candidates() -> &'static [&'static str] {
    #[cfg(target_os = "windows")]
    {
        &[
            r"C:\Program Files\hecate-lampad-desktop\hecate-lampad-desktop.exe",
            r"C:\Program Files\hecate-lampad\hecate-lampad-desktop.exe",
        ]
    }
    #[cfg(not(target_os = "windows"))]
    {
        &[
            "/usr/bin/hecate-lampad-desktop",
            "/usr/local/bin/hecate-lampad-desktop",
        ]
    }
}

pub fn helper_package_installed() -> bool {
    helper_binary_candidates()
        .iter()
        .any(|path| std::path::Path::new(path).exists())
}

#[derive(Debug, Error)]
pub enum DesktopIpcError {
    #[error("helper_unavailable: desktop helper is not connected")]
    HelperUnavailable,
    #[error("no_active_gui_session: {0}")]
    NoActiveGuiSession(String),
    #[error("display_unsupported: {0}")]
    DisplayUnsupported(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("ipc io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipc protocol error: {0}")]
    Protocol(String),
    #[error("{0}")]
    Remote(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

pub fn ipc_token_path(socket_path: &std::path::Path) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = socket_path;
        let base = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("hecate-lampad").join("ipc.token")
    }
    #[cfg(not(windows))]
    {
        socket_path.with_file_name("ipc.token")
    }
}

pub fn read_ipc_token(socket_path: &std::path::Path) -> Result<String, DesktopIpcError> {
    let path = ipc_token_path(socket_path);
    let token = std::fs::read_to_string(&path).map_err(|_| DesktopIpcError::HelperUnavailable)?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(DesktopIpcError::HelperUnavailable);
    }
    Ok(token)
}

/// Generate a 32-byte cryptographically random IPC token (hex-encoded).
pub fn generate_ipc_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time comparison of a provided auth token against the expected value.
pub fn auth_token_ok(provided: Option<&str>, expected: &str) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    if provided.len() != expected.len() {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Write the IPC token. On Unix the mode is `0640` (owner + `hecate-ipc` group):
/// agent and helper run as distinct UIDs, so pure `0600` would make the token
/// unreadable to the peer. World read remains denied.
/// On Windows a protected DACL grants LocalSystem + Administrators + Creator Owner only.
/// Exclusive create + no-follow so a planted symlink cannot redirect the write.
pub fn write_ipc_token(socket_path: &std::path::Path, token: &str) -> Result<(), std::io::Error> {
    let path = ipc_token_path(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() || std::fs::symlink_metadata(&path).is_ok() {
        let _ = std::fs::remove_file(&path);
    }
    {
        use std::io::Write;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            file.write_all(token.as_bytes())?;
            file.sync_all()?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)?;
            file.write_all(token.as_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(any(unix, windows)))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(token.as_bytes())?;
            file.sync_all()?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
        let _ = set_hecate_ipc_group(&path);
    }
    #[cfg(windows)]
    {
        set_windows_ipc_token_acl(&path)?;
    }
    Ok(())
}

/// Protected DACL: SYSTEM + Administrators + Creator Owner (no Users:RX inheritance).
#[cfg(windows)]
fn set_windows_ipc_token_acl(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl = windows::core::w!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;CO)");
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|error| std::io::Error::other(error.message()))?;
    }
    let mut dacl_present = false.into();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted = false.into();
    unsafe {
        GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
            .map_err(|error| {
                let _ = LocalFree(windows::Win32::Foundation::HLOCAL(sd.0));
                std::io::Error::other(error.message())
            })?;
        let result = SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        );
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(sd.0));
        if result.is_err() {
            return Err(std::io::Error::other(format!(
                "SetNamedSecurityInfoW failed: {result:?}"
            )));
        }
    }
    Ok(())
}

/// Best-effort `chgrp hecate-ipc` so the agent service user can read the token.
#[cfg(unix)]
fn set_hecate_ipc_group(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let group = unsafe { libc::getgrnam(CString::new(IPC_GROUP_NAME).unwrap().as_ptr()) };
    if group.is_null() {
        return Ok(());
    }
    let gid = unsafe { (*group).gr_gid };
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set socket permissions to `0660` (owner + group). Pair with shared `hecate-ipc` group.
#[cfg(unix)]
pub fn set_ipc_socket_permissions(socket_path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    let _ = set_hecate_ipc_group(socket_path);
    Ok(())
}

#[cfg(not(unix))]
pub fn set_ipc_socket_permissions(_socket_path: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: String,
    pub ok: bool,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub error: Option<IpcErrorBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub scale: f64,
    pub primary: bool,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopInfoResult {
    pub helper_version: String,
    pub display_backend: String,
    pub session_user: String,
    pub clipboard_supported: bool,
    pub monitors: Vec<MonitorInfo>,
    pub virtual_desktop: VirtualDesktop,
    #[serde(default)]
    pub active_sessions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDesktop {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone)]
pub struct CaptureResult {
    pub meta: Value,
    pub bytes: Vec<u8>,
}

pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn encode_frame(header: &impl Serialize, payload: &[u8]) -> Result<Vec<u8>, DesktopIpcError> {
    let header_bytes =
        serde_json::to_vec(header).map_err(|e| DesktopIpcError::Protocol(e.to_string()))?;
    if header_bytes.len() > u32::MAX as usize || payload.len() > u32::MAX as usize {
        return Err(DesktopIpcError::Protocol("frame too large".into()));
    }
    let mut out = Vec::with_capacity(8 + header_bytes.len() + payload.len());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), DesktopIpcError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let header_len = u32::from_le_bytes(len_buf) as usize;
    if header_len > 16 * 1024 * 1024 {
        return Err(DesktopIpcError::Protocol("header too large".into()));
    }
    let mut header = vec![0u8; header_len];
    reader.read_exact(&mut header).await?;
    reader.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if payload_len > 64 * 1024 * 1024 {
        return Err(DesktopIpcError::Protocol("payload too large".into()));
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok((header, payload))
}

pub fn map_remote_error(error: &IpcErrorBody) -> DesktopIpcError {
    match error.code.as_str() {
        "helper_unavailable" | "unauthorized" => DesktopIpcError::HelperUnavailable,
        "no_active_gui_session" => DesktopIpcError::NoActiveGuiSession(error.message.clone()),
        "display_unsupported" => DesktopIpcError::DisplayUnsupported(error.message.clone()),
        _ => DesktopIpcError::Remote(format!("{}: {}", error.code, error.message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ipc_token_is_64_hex_chars() {
        let token = generate_ipc_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn auth_token_ok_rejects_mismatch() {
        assert!(auth_token_ok(Some("abcd"), "abcd"));
        assert!(!auth_token_ok(Some("abce"), "abcd"));
        assert!(!auth_token_ok(None, "abcd"));
        assert!(!auth_token_ok(Some("abc"), "abcd"));
    }
}
