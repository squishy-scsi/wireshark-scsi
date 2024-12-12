// SPDX-License-Identifier: BSD-3-Clause

#include "linktype_parallel_scsi.hh"

#include "scsi-framer.hh"

#include <functional>
#include <unordered_map>
#include <string>
#include <string_view>
#include <tuple>
#include <format>
#include <print>

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>

using namespace std::literals::string_view_literals;

static dissector_handle_t scsi_framer;

namespace ws_scsi::framer {
	using ws_scsi::common::tvb_from_numeric;
	using ws_scsi::common::tvb_from_string;
	using ws_scsi::linktype::frame_type_t;
	using ws_scsi::linktype::parallel_scsi_t;


	static std::unordered_map<frame_type_t, std::string_view> FRAME_TYPE_NAMES{{
		{ frame_type_t::ARBITRATION,   "Arbitration"sv   },
		{ frame_type_t::BUS_CONDITION, "Bus Condition"sv },
		{ frame_type_t::COMMAND,       "Command"sv       },
		{ frame_type_t::DATA_IN,       "Data-In"sv       },
		{ frame_type_t::DATA_OUT,      "Data-Out"sv      },
		{ frame_type_t::INFORMATION,   "Information"sv   },
		{ frame_type_t::MESSAGE,       "Message"sv       },
		{ frame_type_t::SELECTION,     "Selection"sv     },
		{ frame_type_t::INVALID,       "Invalid"sv       },
	}};


	void dissect_raw(tvbuff_t* const buffer, proto_tree* subtree, const std::int32_t offset) noexcept {
		proto_tree_add_item(subtree, hfFrameData, buffer, offset, -1, ENC_NA);
	}

	[[nodiscard]]
	parallel_scsi_t dissect_header(tvbuff_t* const buffer, proto_tree *const subtree, const std::int32_t offset) noexcept {
		proto_item* frame_header{};
		parallel_scsi_t header{};

		const auto h_length{tvb_get_ntohl(buffer, offset)};
		const auto ftype{tvb_get_uint8(buffer, offset + 4)};
		const auto orig_id{tvb_get_uint8(buffer, offset + 5)};
		const auto dest_id{tvb_get_uint8(buffer, offset + 6)};
		const auto d_len{tvb_get_ntohl(buffer, offset + 7 + 17)};

		header.header_len = h_length;
		header.type = static_cast<frame_type_t>(ftype);
		header.originating_id = orig_id;
		header.destination_id = dest_id;
		header.data_length = d_len;

		proto_tree* const header_tree{proto_tree_add_subtree(subtree, buffer, 0, sizeof(header), ett_frame_header, &frame_header, "Frame Header")};
		proto_tree_add_item(header_tree, hfFrameLength, buffer, offset,      4, BASE_HEX);
		/* TODO(aki): Stringify the frame type */
		proto_tree_add_item(header_tree, hfFrameType,   buffer, offset + 4,  1, BASE_HEX);
		proto_tree_add_item(header_tree, hfOrigID,      buffer, offset + 5,  1, BASE_DEC);
		proto_tree_add_item(header_tree, hfDestID,      buffer, offset + 6,  2, BASE_DEC);
		proto_tree_add_item(header_tree, hfReserved,    buffer, offset + 7,  17, ENC_NA  );
		proto_tree_add_item(header_tree, hfDataLength,  buffer, offset + 24,  4, BASE_HEX);


		return header;
	}

	static int dissector(tvbuff_t* const buffer, packet_info* const pinfo, proto_tree* const tree, void* const) noexcept {
		/* Get the total buffer length */
		const std::uint32_t packet_len{tvb_captured_length(buffer)};

		/* We should try to check which bus we are on and construct the bus type */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Parallel SCSI");

		proto_item* frame;
		proto_tree* const subtree{
			proto_tree_add_subtree(tree, buffer, 0, -1, ett_parallel_scsi_frame, &frame, "Parallel SCSI Frame")
		};

		const auto header{dissect_header(buffer, subtree, 0)};

		if (header.type == frame_type_t::INVALID) {
			/* TODO(aki): Figure out how to get Wireshark to color the column invalid */
		}

		col_append_fstr(pinfo->cinfo, COL_DEF_SRC, "SCSI ID: %d", header.originating_id);
		col_append_fstr(pinfo->cinfo, COL_DEF_DST, "SCSI ID: %d", header.destination_id);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s Frame", FRAME_TYPE_NAMES[header.type].data());

		tvbuff_t *const frame_data = tvb_new_subset_remaining(buffer, sizeof(header));
		dissect_raw(frame_data, subtree, 0);

		return packet_len;
	}

	void register_protoinfo() noexcept {
		scsi_protocol = proto_register_protocol("Parallel SCSI", "Parallel SCSI", "scsi.parallel");

		scsi_framer = register_dissector("parallel_scsi", dissector, scsi_protocol);

		proto_register_field_array(scsi_protocol, fields.data(), fields.size());
		proto_register_subtree_array(ett.data(), ett.size());
	}

	void register_handoff() noexcept { }

	void register_protocol_preferences() noexcept { }

}
