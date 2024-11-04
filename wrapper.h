// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

#ifdef RUST_STD
#include <pci/pci.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <libnvme.h>
#endif

#include <library/spdm_common_lib.h>
#include <library/spdm_crypt_lib.h>
#include <library/spdm_lib_config.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_responder_lib.h>
#include <library/spdm_return_status.h>
#include <library/spdm_secured_message_lib.h>
#include <library/spdm_transport_pcidoe_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <library/spdm_transport_storage_lib.h>
#ifdef LIBSPDM_TESTS
#include <library/spdm_responder_conformance_test_lib.h>
#endif
#include <os_stub/spdm_crypt_ext_lib/spdm_crypt_ext_lib.h>
#include <os_stub/spdm_crypt_ext_lib/cryptlib_ext.h>
#include <internal/libspdm_common_lib.h>
#include <internal/libspdm_requester_lib.h>
#include <industry_standard/pcidoe.h>
#include <industry_standard/spdm_storage_binding.h>