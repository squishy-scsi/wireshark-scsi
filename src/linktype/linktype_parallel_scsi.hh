// SPDX-License-Identifier: BSD-3-Clause
/*
	NOTE(aki): There is no guarantee that this file is in sync with the LINKTYPE_PARALLEL_SCSI
	           standard that is defined in the docs/LINKTYPE_PARALLEL_SCSI.md file of this repo.

			   If this header has been vendored in a third-party project for use the full URL
			   to the standard as it stands is:

			   https://github.com/squishy-scsi/wireshark-scsi/docs/LINKTYPE_PARALLEL_SCSI.md


	NOTE(aki): This file has been written in a way that allows for use in any compliant C++
	           freestanding envrionment. As such it should be useable even in an embedded
			   and/or bare-metal context if needed.
*/
#pragma once
#if !defined(LINKTYPE_PARALLEL_SCSI_HH)
#define LINKTYPE_PARALLEL_SCSI_HH

#include <array>
#include <cstdint>
#include <type_traits>

namespace ws_scsi::linktype {
	enum struct frame_type_t : std::uint8_t {
		COMMAND       = 0x00U,
		DATA_IN       = 0x01U,
		DATA_OUT      = 0x02U,
		MESSAGE       = 0x03U,
		ARBITRATION   = 0x04U,
		SELECTION     = 0x05U,
		INFORMATION   = 0x09U,
		BUS_CONDITION = 0x0FU,

		INVALID       = 0xFFU
	};

	/* Actual frame */
	struct parallel_scsi_t final {
		std::uint32_t header_len{};
		frame_type_t type{frame_type_t::INVALID}; /* Initialize to invalid frame type */
		std::uint8_t originating_id{};
		std::uint8_t destination_id{};
		const std::array<std::uint8_t, 17> _reserved{};
		std::uint32_t data_length{};
		/* data + padding after */
	};

	namespace bus_flags {
		enum struct data_rate_t : std::uint16_t {
			/*      R'XXX'XXXX'XX'X'X'XXXX */
			SDR = 0b0'000'0000'00'0'0'0000U,
			DDR = 0b1'000'0000'00'0'0'0000U
		};

		enum struct bus_speed_t : std::uint16_t {
			/*          X'CCC'XXXX'XX'X'X'XXXX */
			MHZ_5   = 0b0'000'0000'00'0'0'0000U,
			MHZ_10  = 0b0'001'0000'00'0'0'0000U,
			MHZ_20  = 0b0'010'0000'00'0'0'0000U,
			MHZ_40  = 0b0'011'0000'00'0'0'0000U,
			MHZ_80  = 0b0'100'0000'00'0'0'0000U,
			MHZ_160 = 0b0'101'0000'00'0'0'0000U,
		};

		enum struct data_width_t : std::uint16_t {
			/*          X'XXX'WWWW'XX'X'X'XXXX */
			BITS_8  = 0b0'000'0000'00'0'0'0000U,
			BITS_16 = 0b0'000'0001'00'0'0'0000U,
			BITS_32 = 0b0'000'0010'00'0'0'0000U,
		};

		enum struct electrical_type_t : std::uint16_t {
			/*      X'XXX'XXXX'TT'X'X'XXXX */
			HVD = 0b0'000'0000'00'0'0'0000U,
			SE  = 0b0'000'0000'01'0'0'0000U,
			LVD = 0b0'000'0000'10'0'0'0000U,
			MSE = 0b0'000'0000'11'0'0'0000U,
		};

		enum struct precompensation_t : std::uint16_t {
			/*           X'XXX'XXXX'XX'E'X'XXXX */
			DISABLED = 0b0'000'0000'00'0'0'0000U,
			ENABLED  = 0b0'000'0000'00'1'0'0000U,
		};

		enum struct paced_transfer_t : std::uint16_t {
			/*           X'XXX'XXXX'XX'X'E'XXXX */
			DISABLED = 0b0'000'0000'00'0'0'0000U,
			ENABLED  = 0b0'000'0000'00'0'1'0000U,
		};
	};

	/* PCAPNG Interface Description Block Option Value */
	struct bus_options_t final {
		const std::uint32_t pen{0x0000'F578U};
		const std::uint16_t opt_id{0x0000U};
		std::uint16_t bus_flags{0x0000U};
		const std::array<std::uint8_t, 8> _reserved{};
	};

}



using linktype_parallel_scsi = ws_scsi::linktype::parallel_scsi_t;

#endif /* LINKTYPE_PARALLEL_SCSI_HH */
