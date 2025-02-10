// SPDX-License-Identifier: BSD-3-Clause

#include "linktype_parallel_scsi.hh"

#include "common.hh"
#include "proto-scsi.hh"

#include <functional>
#include <unordered_map>
#include <string>
#include <string_view>
#include <tuple>
#include <format>
#include <print>

WS_SCSI_DIAGNOSTICS_PUSH()
WS_SCSI_DIAGNOSTICS_IGNORE("-Wsign-conversion")
WS_SCSI_DIAGNOSTICS_IGNORE("-Warith-conversion")
WS_SCSI_DIAGNOSTICS_IGNORE("-Wpedantic")
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <wiretap/wtap.h>
WS_SCSI_DIAGNOSTICS_POP()


using ws_scsi::linktype::frame_type_t;
using ws_scsi::linktype::parallel_scsi_t;

using namespace std::literals::string_view_literals;


static std::array<value_string, 9> frame_type_str{{
	{ static_cast<std::uint32_t>(frame_type_t::ARBITRATION),   "Arbitration"   },
	{ static_cast<std::uint32_t>(frame_type_t::BUS_CONDITION), "Bus Condition" },
	{ static_cast<std::uint32_t>(frame_type_t::COMMAND),       "Command"       },
	{ static_cast<std::uint32_t>(frame_type_t::DATA_IN),       "Data-In"       },
	{ static_cast<std::uint32_t>(frame_type_t::DATA_OUT),      "Data-Out"      },
	{ static_cast<std::uint32_t>(frame_type_t::INFORMATION),   "Information"   },
	{ static_cast<std::uint32_t>(frame_type_t::MESSAGE),       "Message"       },
	{ static_cast<std::uint32_t>(frame_type_t::SELECTION),     "Selection"     },
	{ static_cast<std::uint32_t>(frame_type_t::INVALID),       "Invalid"       },
}};

/* PROTO: `parallel_scsi` */
static std::int32_t PROTO_SCSI{-1};
static expert_module_t* PROTO_SCSI_EM{nullptr};
static dissector_handle_t PROTO_SCSI_HNDL{nullptr};

static std::int32_t ett_scsi_linktype_header{-1};
static std::int32_t ett_scsi_linktype_data{-1};

static std::array<std::int32_t*, 2> ett_scsi{{
	&ett_scsi_linktype_header,
	&ett_scsi_linktype_data,
}};

/* Fields: Frame Header */
static std::int32_t hf_frame_length{-1};
static std::int32_t hf_frame_type{-1};
static std::int32_t hf_orig_id{-1};
static std::int32_t hf_dest_id{-1};
static std::int32_t hf_reserved{-1};
static std::int32_t hf_data_length{-1};
/* Fields: Frame Data*/
static std::int32_t hf_frame_data{-1};

static std::array<hf_register_info, 7> fields_scsi{{
	/* Fields: Frame Header */
	{ &hf_frame_length, {
		"Header Length", "scsi.parallel.frame.length",
		FT_INT32, BASE_DEC, nullptr, 0,
		"Length of the parallel SCSI capture frame header.",
		HFILL
	} },
	{ &hf_frame_type, {
		"Frame Type", "scsi.parallel.frame.type",
		FT_UINT8, BASE_HEX, VALS(frame_type_str.data()), 0,
		"Type of the parallel SCSI capture frame",
		HFILL
	} },
	{ &hf_orig_id, {
		"Originating ID", "scsi.parallel.frame.id.orig",
		FT_INT8, BASE_DEC, nullptr, 0,
		"SCSI ID of the originator of this capture frame",
		HFILL
	} },
	{ &hf_dest_id, {
		"Destination ID", "scsi.parallel.frame.id.dest",
		FT_INT8, BASE_DEC, nullptr, 0,
		"SCSI ID of the target of this capture frame",
		HFILL
	} },
	{ &hf_reserved, {
		"Reserved", "scsi.parallel.frame.reserved",
		FT_BYTES, BASE_NONE, nullptr, 0,
		"Reserved header space",
		HFILL
	} },
	{ &hf_data_length, {
		"Data Length", "scsi.parallel.frame.data_length",
		FT_INT32, BASE_DEC, nullptr, 0,
		"Length of the raw data from the parallel SCSI capture",
		HFILL
	} },
	/* Fields: Frame Data*/
	{ &hf_frame_data, {
		"Capture Data", "scsi.parallel.frame.data",
		FT_BYTES, BASE_NONE, nullptr, 0,
		"Capture Data",
		HFILL
	} },
}};


static expert_field ei_scsi_invalid_frametype = EI_INIT;

static std::array<ei_register_info, 1> ei_scsi{{
	{ &ei_scsi_invalid_frametype, {
		"scsi.parallel.invalid_frame_type", PI_PROTOCOL, PI_ERROR,
		"Invalid SCSI frame type",
		EXPFILL
	} },
}};

namespace scsi::proto {

	static std::int32_t dissect_scsi(tvbuff_t* const buffer, packet_info* const pinfo, proto_tree* const tree, void* const) noexcept {
		/* Get the total buffer length */
		const std::int32_t packet_len{tvb_captured_length(buffer)};

		auto scsi_tree_item{proto_tree_add_item(tree, PROTO_SCSI, buffer, 0, sizeof(parallel_scsi_t), ENC_NA)};
		auto scsi_tree{proto_item_add_subtree(scsi_tree_item, ett_scsi_linktype_header)};

		/* Extract Header */
		parallel_scsi_t header{};

		const auto header_len{tvb_get_ntohl(buffer, 0)};
		const auto frame_type{tvb_get_uint8(buffer, 4)};
		const auto orig_id{tvb_get_uint8(buffer, 5)};
		const auto dest_id{tvb_get_uint8(buffer, 6)};
		const auto data_len{tvb_get_ntohl(buffer, 24)};

		header.header_len = header_len;
		if (frame_type > static_cast<std::uint8_t>(frame_type_t::BUS_CONDITION)) {
			header.type = frame_type_t::INVALID;
		} else {
			header.type = static_cast<frame_type_t>(frame_type);
		}
		header.originating_id = orig_id;
		header.destination_id = dest_id;
		header.data_length = data_len;

		/* Add the protocol items */
		proto_tree_add_item(scsi_tree, hf_frame_length, buffer,  0,  4, BASE_HEX);
		proto_tree_add_item(scsi_tree, hf_frame_type,   buffer,  4,  1, BASE_HEX);
		proto_tree_add_item(scsi_tree, hf_orig_id,      buffer,  5,  1, BASE_HEX);
		proto_tree_add_item(scsi_tree, hf_dest_id,      buffer,  6,  1, BASE_HEX);
		proto_tree_add_item(scsi_tree, hf_reserved,     buffer,  7, 17, ENC_NA);
		proto_tree_add_item(scsi_tree, hf_data_length,  buffer, 24,  4, BASE_HEX);

		if (header.type == frame_type_t::INVALID) {
			expert_add_info(pinfo, scsi_tree_item, &ei_scsi_invalid_frametype);
		}

		/* TODO(aki): We should try to check which bus we are on and construct the bus type */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Parallel SCSI");

		col_append_fstr(pinfo->cinfo, COL_DEF_SRC, "SCSI ID: %d", header.originating_id);
		col_append_fstr(pinfo->cinfo, COL_DEF_DST, "SCSI ID: %d", header.destination_id);

		return packet_len;
	}


	static void register_parallel_scsi_protoinfo() noexcept {
		/* NOTE(aki): Due to wireshark already having a 'scsi' protocol, we are 'scsi.parallel' */
		PROTO_SCSI = proto_register_protocol(
			"Parallel SCSI Capture", "Parallel SCSI", "scsi.parallel"
		);

		proto_register_field_array(PROTO_SCSI, fields_scsi.data(), fields_scsi.size());

		PROTO_SCSI_EM = expert_register_protocol(PROTO_SCSI);
		expert_register_field_array(PROTO_SCSI_EM, ei_scsi.data(), ei_scsi.size());

		PROTO_SCSI_HNDL = register_dissector("parallel_scsi", dissect_scsi, PROTO_SCSI);
	}

	void register_protoinfo() noexcept {
		proto_register_subtree_array(ett_scsi.data(), ett_scsi.size());

		/* Register the base proto */
		register_parallel_scsi_protoinfo();

	}

	void register_handoff() noexcept {
		if (PROTO_SCSI_HNDL != nullptr) {
			dissector_add_uint("wtap_encap", WTAP_ENCAP_USER9, PROTO_SCSI_HNDL);
		}
	}

	void register_protocol_preferences() noexcept { }
}
