# SPDX-License-Identifier: BSD-3-Clause
# NOTE: This file is for Windows compatibility only
# If you are building on Linux, use the meson build system

include(WiresharkPlugin)

set_module_info(proto-scsi 0 1 0 0)

add_definitions(-DWIRESHARK_VERSION_MAJOR=${PROJECT_MAJOR_VERSION} -DWIRESHARK_VERSION_MINOR=${PROJECT_MINOR_VERSION})

set(DISSECTOR_SRC
	proto-scsi.cc
)

set(PLUGIN_FILES
	wireshark-scsi.cc
	${DISSECTOR_SRCS}
)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS} "
)

register_plugin_files(plugin.c
	proto-scsi
	${DISSECTOR_SRCS}
)

add_plugin_library(proto-scsi epan)
target_link_libraries(proto-scsi epan)
install_plugin(proto-scsi epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.hh")
CHECKAPI(
	NAME
		proto-scsi
	SWITCHES
		-g abort -g termoutput
	SOURCES
		${DISSECTOR_SRCS}
		${DISSECTOR_HEADERS}
)
