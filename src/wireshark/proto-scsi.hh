// SPDX-License-Identifier: BSD-3-Clause

#pragma once
#if !defined(WIRESHARK_SCSI_PROTO_SCSI_HH)
#define WIRESHARK_SCSI_PROTO_SCSI_HH

namespace scsi::proto {
	void register_protoinfo() noexcept;
	void register_handoff() noexcept;
	void register_protocol_preferences() noexcept;
}

#endif /* WIRESHARK_SCSI_PROTO_SCSI_HH */
