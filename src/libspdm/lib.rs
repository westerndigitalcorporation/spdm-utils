// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! The starting point for SPDM-Utils.
//!
//! For more details see the help information printed by the binary
//! (which is generated from here) or the README
//!

#![cfg_attr(feature = "no_std", no_std)]

#[macro_use]
extern crate log;
extern crate alloc;

#[macro_use]
pub mod libspdm_rs;
#[cfg(not(feature = "no_std"))]
pub mod manifest;
#[macro_use]
pub mod spdm;
pub mod responder;
