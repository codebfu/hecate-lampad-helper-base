//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared policy primitives and IPC wire protocol for Hecate lampad helpers.

pub mod policy;

#[cfg(feature = "ipc")]
mod ipc;

#[cfg(feature = "ipc")]
pub use ipc::*;
