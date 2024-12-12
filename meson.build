# SPDX-License-Identifier: BSD-3-Clause

project(
	'wireshark-scsi',
	'cpp',
	default_options: [
		'buildtype=release',
		'cpp_std=c++23',
		'warning_level=3',
		'b_lto=true',
		'b_ndebug=if-release',
	],
	meson_version: '>= 1.4.0',
	license: 'BSD-3-Clause',
	version: '0.1.0'
)

cxx = meson.get_compiler('cpp')
if get_option('cpp_std') not in ['c++23', 'gnu++23']
	error('Unsupported C++ Version @0@, must be c++23/gnu++23 or newer'.format(get_option('cpp_std')))
endif

extended_warnings = [
	'-Wdouble-promotion',
	'-Wformat=2',
	'-Wformat-overflow=2',
	'-Wformat-signedness',
	'-Wformat-truncation',
	'-Wnull-dereference',
	'-Wmissing-attributes',
	'-Wmissing-braces',
	'-Wsequence-point',
	'-Werror=return-type',
	'-Wunused',
	'-Wunused-local-typedefs',
	'-Wunused-const-variable=2',
	'-Wmaybe-uninitialized',
	'-Wunknown-pragmas',
	'-Wstrict-aliasing',
	'-Wstrict-overflow=3',
	'-Wstring-compare',
	'-Wstringop-overflow',
	'-Warith-conversion',
	'-Wvla-parameter',
	'-Wduplicated-branches',
	'-Wshadow=local',
	'-Wunsafe-loop-optimizations',
	'-Wbad-function-cast',
	'-Wcast-qual',
	'-Wcast-align=strict',
	'-Wcast-function-type',
	'-Wconversion',
	'-Wdangling-else',
	'-Wsign-conversion',
	'-Wfloat-conversion',
	'-Wredundant-decls',
	'-Wvla',
	'-Wstack-protector',
	'-Wunsuffixed-float-constant',
	'-Wimplicit-fallthrough',
	'-Wxor-used-as-pow',
	'-Wself-move',
	'-Wdangling-reference',
	'-Werror=switch',
]

extra_flags = [ ]

mtune = get_option('mtune')

# Because this is added prior to add_project_arguments we don't need to gate it
# on compiler support
if mtune != 'default'
	extra_flags += f'-mtune=@mtune@'
endif

add_project_arguments(
	cxx.get_supported_arguments(extended_warnings),
	language: 'cpp'
)

add_project_arguments(
	cxx.get_supported_arguments(extra_flags),
	language: 'cpp'
)

git = find_program('git', required: false, native: true)

if target_machine.system() != 'windows'
	wireshark = dependency('wireshark', required: true)
	subdir('src')
else
	error('Building the Wireshark dissector on Windows requires extra steps. See the `BUILDING_ON_WINDOWS.md` file in the `src/dissectors/wireshark` directory')
endif
