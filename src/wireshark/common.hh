// SPDX-License-Identifier: BSD-3-Clause
#pragma once
#if !defined(WIRESHARK_SCSI_COMMON_HH)
#define WIRESHARK_SCSI_COMMON_HH

// NOLINTBEGIN(cppcoreguidelines-macro-usage)

#if WIRESHARK_VERSION_MAJOR >= 3 && WIRESHARK_VERSION_MINOR > 2
#	define BITMASK_CONST
#else
#	define BITMASK_CONST const
#endif

/* Allows us to defined pragmas via a macro */
#if defined(__GNUC__) || defined(__clang__)
#	define WS_SCSI_PRAGMA_(p) _Pragma(#p)
#	define WS_SCSI_PRAGMA(p) WS_SCSI_PRAGMA_(p)
#else
# 	define WS_SCSI_PRAGMA(p)
#endif

/* This is here we can squash warnings from external libraries */
/* as our warning policy is quite verbose, for a good reason too. */
#if defined(__GNUG__) && !defined(__clang__)
#	define WS_SCSI_DIAGNOSTICS_PUSH() WS_SCSI_PRAGMA(GCC diagnostic push)
#	define WS_SCSI_DIAGNOSTICS_POP()  WS_SCSI_PRAGMA(GCC diagnostic pop)
#	define WS_SCSI_DIAGNOSTICS_IGNORE(DIAG_NAME) WS_SCSI_PRAGMA(GCC diagnostic ignored DIAG_NAME)
#	define WS_SCSI_POISON(IDENT) WS_SCSI_PRAGMA(GCC poison IDENT)
#elif defined(__clang__)
#	define WS_SCSI_DIAGNOSTICS_PUSH()     \
	WS_SCSI_PRAGMA(clang diagnostic push) \
	WS_SCSI_DIAGNOSTICS_IGNORE("-Wunknown-warning-option")
#	define WS_SCSI_DIAGNOSTICS_POP()  WS_SCSI_PRAGMA(clang diagnostic pop)
#	define WS_SCSI_DIAGNOSTICS_IGNORE(DIAG_NAME) WS_SCSI_PRAGMA(clang diagnostic ignored DIAG_NAME)
#	define WS_SCSI_POISON(IDENT) WS_SCSI_PRAGMA(clang poison IDENT)
#else
#	define WS_SCSI_DIAGNOSTICS_PUSH()
#	define WS_SCSI_DIAGNOSTICS_POP()
#	define WS_SCSI_DIAGNOSTICS_IGNORE(DIAG_NAME)
#	define WS_SCSI_POISON(IDENT)
#endif

// NOLINTEND(cppcoreguidelines-macro-usage)

#include <cstring>
#include <cstdint>
#include <type_traits>
#include <string_view>
#include <tuple>


WS_SCSI_DIAGNOSTICS_PUSH()
WS_SCSI_DIAGNOSTICS_IGNORE("-Wsign-conversion")
WS_SCSI_DIAGNOSTICS_IGNORE("-Warith-conversion")
WS_SCSI_DIAGNOSTICS_IGNORE("-Wpedantic")
#include <epan/packet.h>
WS_SCSI_DIAGNOSTICS_POP()

namespace ws_scsi::common {
	inline tvbuff_t* tvb_from_string(const std::string_view& str) noexcept {
		const auto str_len{str.length() + 1};
		return tvb_new_real_data(
			reinterpret_cast<const std::uint8_t*>(str.data()),
			static_cast<unsigned int>(str_len),
			static_cast<int>(str_len)
		);
	}

	[[gnu::nonnull(1)]]
	inline tvbuff_t* tvb_from_string(const char* const str) noexcept {
		const std::size_t len = strlen(str) + 1;
		return tvb_new_real_data(
			reinterpret_cast<const std::uint8_t*>(str),
			static_cast<unsigned int>(len),
			static_cast<int>(len)
		);
	}

	template<typename T>
	[[gnu::nonnull(1)]]
	inline std::enable_if_t<std::is_integral_v<T>, tvbuff_t*>
	tvb_from_numeric(T* number) noexcept {
		return tvb_new_real_data(reinterpret_cast<uint8_t *>(number), sizeof(number), sizeof(number));
	}
}

#endif /* WIRESHARK_SCSI_COMMON_HH */
