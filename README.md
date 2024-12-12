# wireshark-scsi

This repository contains 2 primary things, the first is the draft/living standard for the [`LINKTYPE_PARALLEL_SCSI`] format, the second being the [wireshark dissector] for said linktype
format, along with more rich SCSI dissectors.

## Building

You need the following prerequisites

 * git
 * meson
 * ninja
 * g++ >= 12 or clang++ >= 15
 * wireshark

To setup the meson project:
```
$ meson setup build
```

Then to build:

```
$ ninja -C build
$ ninja -C build install
```

The dissector will be in `build/src/wireshark/parallel_scsi.so`, it can be installed by symlinking it to `$HOME/.local/lib/wireshark/<VER>/epan/parallel_scsi.so`

## Building On Windows

To build the Wireshark dissectors on windows, first go though the steps in the [Windows Build Instructions] in the Wireshark developer manual to ensure you can build Wireshark correctly. One change is to replace the line `set(CMAKE_CXX_STANDARD 11)` to `set(CMAKE_CXX_STANDARD 20)` in the base `CMakeLists.txt` file in the Wireshark source root directory. Once that is done, you can follow the steps below:

1. copy the contents of the `src/wireshark/` directory into the `plugins/epan/parallel_scsi` directory in the Wireshark source tree. You will need to create said directory.
2. In the root of the Wireshark source directory, change the name of `CMakeListsCustom.txt.example` to `CMakeListsCustom.txt` and add the path to the `parallel_scsi` dissector to the `CUSTOM_PLUGIN_SRC_DIR` set statement, it should look like the following:
	```cmake
	set(CUSTOM_PLUGIN_SRC_DIR
		plugins/epan/
	)
	```
3. Run the Wireshark build, if everything goes correctly then the native dissector will be in `run/<BUILD_TYPE>/plugins/<WS_VERSION>/epan/` directory as `parallel_scsi.dll`

This file can then be used put in your local Wireshark plugins directory and used.s

## License

Nyx is licensed under the [BSD-3-Clause], the full text of which can be found in the [LICENSE] file.

[`LINKTYPE_PARALLEL_SCSI`]: ./docs/LINKTYPE_PARALLEL_SCSI.md
[wireshark dissector]: ./src/wireshark

[Windows Build Instructions]: https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWindows.html

[BSD-3-Clause]: https://spdx.org/licenses/BSD-3-Clause.html
[LICENSE]: ./LICENSE
