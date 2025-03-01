# SPDX-License-Identifier: BSD-3-Clause

config = configuration_data()
config.set('AUTOGEN_HEADER', '/* THIS FILE IS AUTOGENERATED, DO NOT EDIT */')
## Version Information
config.set('COMPILER_NAME', cxx.get_id())
config.set('COMPILER_VERSION', cxx.version())
## Platform information
config.set('TARGET_SYS', target_machine.system())
config.set('TARGET_ARCH', target_machine.cpu())

config.set('BUILD_SYS', build_machine.system())
config.set('BUILD_ARCH', build_machine.cpu())

## Install Details
config.set('INSTALL_PREFIX', get_option('prefix'))

## Misc
config.set('BUGREPORT_URL', get_option('bugreport_url'))

if git.found()
	git_hash = run_command(git, 'rev-parse', '--short', 'HEAD', check: false).stdout().strip()
	if run_command(git, 'diff', '--quiet', check: false).returncode() != 0
		git_hash += '-dirty'
	endif
	config.set('GIT_HASH', git_hash)
	if git_hash != ''
		git_hash = '-@0@'.format(git_hash)
	endif

	describe = run_command(git, 'describe', '--tag', check: false)
	if describe.returncode() == 0
		config.set('VERSION_NUMBER', describe.stdout().strip())
		config.set('VERSION_NUMBER_FULL', '@0@@1@'.format(describe.stdout().strip(), git_hash))
	else
		config.set('VERSION_NUMBER', meson.project_version())
		config.set('VERSION_NUMBER_FULL', '@0@@1@'.format(meson.project_version(), git_hash))
	endif

else
	config.set('VERSION_NUMBER', meson.project_version())
	config.set('GIT_HASH', '???????')
endif

configure_file(
	configuration: config,
	input: 'config.hh.in',
	output: 'config.hh'
)

srcs = files([
	# LINKTYPE_PARALLEL_SCSI protocol definition
	'proto-scsi.cc',
	# Wireshark plugin entrypoint
	'wireshark-scsi.cc',
])

ws_version = wireshark.version()
ws_version = ws_version.split('.')

shared_library(
	'proto-scsi',
	srcs,
	name_prefix: '',
	cpp_args: [
		'-DWS_BUILD_DLL',
		'-DHAVE_PLUGINS',
		'-DWIRESHARK_VERSION_MAJOR=@0@'.format(ws_version[0]),
		'-DWIRESHARK_VERSION_MINOR=@0@'.format(ws_version[1])
	],
	include_directories: [ linktype_api, ],
	dependencies: [ wireshark, ],
	gnu_symbol_visibility: 'inlineshidden',
	install: true,
	install_dir: wireshark.get_variable('plugindir')
)
