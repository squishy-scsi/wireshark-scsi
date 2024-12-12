// SPDX-License-Identifier: BSD-3-Clause
/* External Wireshark Plugin ABI */

#include "config.hh"
#include "common.hh"
#include "scsi-framer.hh"

#include <wsutil/plugins.h>
#include <epan/packet.h>

extern "C" {
	WS_DLL_PUBLIC_DEF extern const char plugin_version[];
	WS_DLL_PUBLIC_DEF extern const int plugin_want_major;
	WS_DLL_PUBLIC_DEF extern const int plugin_want_minor;
	WS_DLL_PUBLIC void plugin_register() noexcept;
	WS_DLL_PUBLIC std::uint32_t plugin_describe() noexcept;
}

const char plugin_version[] = WS_SCSI_VERSION_FULL;
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

/* LINKTYPE_PARALLEL_SCSI protocol */
const static proto_plugin scsi_framer{
	.register_protoinfo = ws_scsi::framer::register_protoinfo,
	.register_handoff   = ws_scsi::framer::register_handoff
};

void plugin_register() noexcept {
	proto_register_plugin(&scsi_framer);
}

std::uint32_t plugin_describe() noexcept {
	return WS_PLUGIN_DESC_DISSECTOR;
}
