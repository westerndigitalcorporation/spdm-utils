// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2026, Western Digital Corporation or its affiliates.

use core::ffi::c_void;
use libspdm::libspdm_rs;
use libspdm::spdm::{LibspdmReturnStatus, TransportLayer};
use std::net::{TcpListener, TcpStream};
use std::ptr;

/// State of the TCP device. Stored as part of `libspdm_context_t`
/// in the `app_context_data_ptr` and accessed via
/// `LIBSPDM_DATA_APP_CONTEXT_DATA`
///
/// The Rust attach_state() and state_from_context() functions save
/// and restore the state.
#[derive(Default)]
pub struct TcpDeviceState {
    /// The stream connected to the peer.
    pub stream: Option<TcpStream>,
    /// The accepted connection listener, used by the server to accept new
    /// connections if the client drops.
    pub listener: Option<TcpListener>,
    /// Server only: if the client drops, keep the server alive.
    pub server_persist: bool,
    /// The transport protocol used to frame the messages on the wire.
    pub transport: Option<TransportLayer>,
}

/// # Summary
///
/// Attaches the `TcpDeviceState` to the SPDM `context` via libspdm's
/// `app_context_data_ptr`, taking ownership of `state`.
///
/// # Parameter
///
/// * `context`: The SPDM context
/// * `state`: The `TcpDeviceState` to attach
///
/// # Panics
///
/// Panics if the state could not be attached to the SPDM context.
pub fn attach_state(context: *mut c_void, state: Box<TcpDeviceState>) {
    let parameter = libspdm_rs::libspdm_data_parameter_t::new_local(0);
    let state_ptr = Box::into_raw(state) as *mut c_void;

    let ret = unsafe {
        libspdm_rs::libspdm_set_data(
            context,
            libspdm_rs::libspdm_data_type_t_LIBSPDM_DATA_APP_CONTEXT_DATA,
            &parameter as *const libspdm_rs::libspdm_data_parameter_t,
            &state_ptr as *const *mut c_void as *const c_void,
            core::mem::size_of::<*mut c_void>(),
        )
    };

    assert!(
        !LibspdmReturnStatus::libspdm_status_is_error(ret),
        "Failed to attach TCP device state to the SPDM context"
    );
}

/// # Summary
///
/// Get the `TcpDeviceState` attached to the SPDM `context`, see
/// `attach_state()` for details.
///
/// # Parameter
///
/// * `context`: The SPDM context
///
/// # Returns
///
/// A pointer to the `TcpDeviceState`
///
/// # Panics
///
/// Panics if no `TcpDeviceState` is attached to the SPDM context.
pub fn state_from_context(context: *mut c_void) -> *mut TcpDeviceState {
    let parameter = libspdm_rs::libspdm_data_parameter_t::new_local(0);
    let mut state_ptr: *mut c_void = ptr::null_mut();
    let mut data_size = core::mem::size_of::<*mut c_void>();

    let ret = unsafe {
        libspdm_rs::libspdm_get_data(
            context,
            libspdm_rs::libspdm_data_type_t_LIBSPDM_DATA_APP_CONTEXT_DATA,
            &parameter as *const libspdm_rs::libspdm_data_parameter_t,
            &mut state_ptr as *mut *mut c_void as *mut c_void,
            &mut data_size,
        )
    };

    assert!(
        !LibspdmReturnStatus::libspdm_status_is_error(ret),
        "Failed to get TCP device state from the SPDM context"
    );
    assert!(!state_ptr.is_null(), "No TCP device state in SPDM context");

    state_ptr as *mut TcpDeviceState
}
