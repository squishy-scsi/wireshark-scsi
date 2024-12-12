// SPDX-License-Identifier: BSD-3-Clause

#pragma once
#if !defined(WIRESHARK_SCSI_FRAMER_HH)
#define WIRESHARK_SCSI_FRAMER_HH

#include "common.hh"

#include <array>
#include <cstdint>

#include <epan/conversation.h>
#include <epan/packet.h>

namespace ws_scsi::framer {

	static std::int32_t scsi_protocol{-1};

	static std::int32_t ett_parallel_scsi_frame{-1};
	static std::int32_t ett_frame_header{-1};

	/* Frame Header */
	static std::int32_t hfFrameLength{-1};
	static std::int32_t hfFrameType{-1};
	static std::int32_t hfOrigID{-1};
	static std::int32_t hfDestID{-1};
	static std::int32_t hfReserved{-1};
	static std::int32_t hfDataLength{-1};

	/* Frame Data */
	static std::int32_t hfFrameData{-1};

	static std::array<std::int32_t*, 2> ett{{
		&ett_parallel_scsi_frame,
		&ett_frame_header,
	}};

	static std::array<hf_register_info, 7> fields{{
		{ &hfFrameLength, {
			"Frame Length", "scsi.parallel.frame.length",
			FT_INT32, BASE_DEC, nullptr, 0, nullptr, HFILL
		} },
		{ &hfFrameType, {
			"Frame Type", "scsi.parallel.frame.type",
			FT_STRING, ENC_ASCII, nullptr, 0, nullptr, HFILL
		} },
		{ &hfOrigID, {
			"Originating ID", "scsi.parallel.frame.header.orig",
			FT_INT8, BASE_DEC, nullptr, 0, nullptr, HFILL
		} },
		{ &hfDestID, {
			"Destination ID", "scsi.parallel.frame.header.dest",
			FT_INT8, BASE_DEC, nullptr, 0, nullptr, HFILL
		} },
		{ &hfReserved, {
			"Reserved", "scsi.parallel.frame.header.reserved",
			FT_BYTES, BASE_NONE, nullptr, 0, nullptr, HFILL
		} },
		{ &hfDataLength, {
			"Data Length", "scsi.parallel.frame.header.data_len",
			FT_INT32, BASE_DEC, nullptr, 0, nullptr, HFILL
		} },
		{ &hfFrameData, {
			"Frame Data", "scsi.parallel.frame.data",
			FT_BYTES, BASE_NONE, nullptr, 0, nullptr, HFILL
		} },
	}};


	void register_protoinfo() noexcept;
	void register_handoff() noexcept;
	void register_protocol_preferences() noexcept;
}
#endif /* WIRESHARK_SCSI_FRAMER_HH */
