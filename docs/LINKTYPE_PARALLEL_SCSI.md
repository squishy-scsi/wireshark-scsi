# `LINKTYPE_PARALLEL_SCSI`

> [!CAUTION]
> This is still vastly in flux, and will be modified as new needs are found.
> If you are adding support to your application, make sure to note which version of this document you're
> implementing, (use the git rev for the version in this repo).


This document defines a [tcpdump] [`LINKTYPE_`] to encapsulate raw SCSI traffic. This is done by adding framing around the raw SCSI commands and bus status with [Transfer Frames], potentially able to represent an almost full reconstruction of the state of the SCSI bus.


This is being done for a few reasons:

1. There are no existing raw SCSI dissectors, they all operate off of either [Fibre Channel], [iSCSI], or [something else].
2. Existing SCSI dissectors rely on either explicit setting of what type of SCSI traffic is there or the lower-level framing (see 1)


While out of place, we also define [ancillary information] on how we expect to store SCSI captures within [PCAPNG] files, such as values for the [Interface Description Block] and it's associated [Option Blocks].

## Format

The framing format is made up of a larger outer frame called the [Transfer Frame], which contains metadata about the transfer and the raw transfer data, along with any important bus state.

You can find example and test PCAPNG files in the [`examples`] directory in the root of the [wireshark-scsi] git repository (this repository).

### Type Definitions

> [!IMPORTANT]
> The frame layout, fields, and diagrams are all in **BIG ENDIAN** (also known as [network order])

The following types are used within the definition of the the `LINKTYPE_PARALLEL_SCSI` frames and fields:
* `i8`/`u8`: signed/unsigned 8-bit (1 byte/octet) integer type.
* `i16`/`u16`: signed/unsigned 16-bit (2 byte/octet) integer type.
* `i24`/`u24`: signed/unsigned 24-bit (3 byte/octet) integer type.
* `i32`/`u32`: signed/unsigned 32-bit (4 byte/octet) integer type.
* `f8`/`f16`/`f24`/`f32`: 8/16/24/32-bit wide flags field.
  > **NOTE**: Not all flags in a flags field may be the same size, see field definition for details on layout.
* `bytes`: array of unsigned bytes.
  > **NOTE**: There is no terminator ordinal for a `bytes` field, they are normally prefixed with their length, you can think of them as `u32` length-prefixed arrays of `u8`'s.

### Transfer Frame

A transfer frame is the encapsulation structure for `LINKTYPE_PARALLEL_SCSI` capture data, it is structured as follows:

> [!WARNING]
> TODO(aki): We need some specialization on `Frame Type` to define the `Data` if it's more specialized
> (e.g. not just a command or message blob).

```
    0             0               1               2               3
    0             7               5               3               1
   ╭┴─────────────┴───────────────┴───────────────┴───────────────┴╮
 0 │                        Header Length                          │
   ├───────────────┬───────────────┬───────────────┬───────────────┤
 4 │  Frame Type   │    Orig ID    │    Dest ID    │               │
   ├───────────────┴───────────────┴───────────────╯               │
 8 │                                                               │
   │                                                               │
12 │                                                               │
   │                            Reserved                           │
16 │                                                               │
   │                                                               │
24 │                                                               │
   ├───────────────────────────────────────────────────────────────┤
32 │                          Data Length                          │
   ├───────────────────────────────────────────────────────────────┤
36 ┊                                                               ┊
   ┊                             Data                              ┊
   ┊                                                               ┊
   ├───────────────────────────────────────────────────────────────┤
   ┊                            Padding                            ┊
   ╰┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄╯
```

> [!NOTE]
> Do we want some sort of checksum or magic number in the frame header?
> Would give a small perf cost, but allow dissectors to ensure the frame is
> valid.

The structure fields shown above are defined as follows:

* Header Length (`u32`)
  > The total length of the frame header, including `Data Length` but not including `Data` itself.
  > This should total `28`
* Frame Type (`u8`)
  > An enumerated value defining the type of data that this frame describes.
  >
  > The values are as follows:
  > * `0x00` - Command
  > * `0x01` - Data-in
  > * `0x02` - Data-out
  > * `0x03` - Message
  > * `0x04` - Arbitration
  > * `0x05` - Selection/Reselection
  > * `0x09` - Information Unit
  > * `0x0F` - Bus Condition
  > * `0xFF` - Invalid Frame/Reserved
* Orig ID (`u8`)
  > The SCSI ID of the device originating the data within the frame, if applicable
* Dest ID (`u8`)
  > The SCSI ID of the destination device for the data within the frame, if applicable
* Reserved (`bytes`)
  > 17 bytes reserved for future use, must be set to `0x00`
* Data Length (`u32`)
  > Length of the `Data` field.
* Data (`bytes`)
  > The raw SCSI transfer data
* Padding
  > Frame padding to the nearest 32-bit boundary, to comply with [PCAPNG Block alignment requirements], must be `0x0`,
  > this is optional if `Data` ends up being aligned to the boundary itself.

### Frame Capture Storage

When storing `LINKTYPE_PARALLEL_SCSI` frames into [PCAPNG] files for use in protocol analyzer, we follow the standard [block hierarchy], and leverage the [Interface Description Block] (`IDB`), [Interface Statistics Block] (`ISB`), and [Enhanced Packet Blocks] (EPB), that is why we don't store related bus metadata within the frames themselves.

#### Interface Description Block

The [Interface Description Block] is configured as follows:
* The `LinkType` field is set to `DLT_USER7` (`154`)
  > **NOTE:** See the [Standardization] section for notes about reserved DLT use
* `SnapLen` should be set to `0`.
  > **NOTE:** If capture space is a serious concern, ensure that the value is set to the size of the `LINKTYPE_PARALLEL_SCSI` transfer frame header and padding in addition to the desired capture length, otherwise capture data truncation loss will occur.
* The following `IDB` options **may** be set:
  * [`if_name`] - Interface Name (e.g. `SCSI0`)
  * [`if_description`] - Interface Description
* The following `IDB` options **must** be set:
  * [`if_hardware`] - The name of the hardware that did the capture (e.g. `SCSI Bus Analyzer rev8`)
  * Our [Bus Metadata] option block.

#### Enhanced Packet Blocks

The [Enhanced Packet Blocks] are used to encapsulate the `LINKTYPE_PARALLEL_SCSI` [Transfer Frames], they should be configures as follows:
* The `Interface ID` field set to the appropriate SCSI Bus ID
  > **NOTE:** This is not the ID of the *device* on the SCSI bus, but the ID of the SCSI bus itself which is described by the Interface Description Block. see [multi-bus capture] for further information.
* `Captured Packet Length` and `Original Packet Length` should be set to the size of transfer frame in this packet.
  > **NOTE:** iff capture truncation can occur or it is enabled, then `Original Packet Length` should be set to the full frame capture length plus the transfer frame header, while `Captured Packet Length` should be the configured/truncated size plus the frame header size.
  >
  > For example, if a transfer of `8KiB` was truncated to `1KiB`, then `Captured Packet Length` is `1KiB + sizeof(frame_header)`  and `Original Packet Length` is `8KiB + sizeof(frame_header)`.
  >
  > Truncation is highly advised against if at all possible, as the full data stream from a transaction will be unrecoverable, but this may be unreasonable if a capture is being done on an embedded device with storage constraints.
* `Packet Data` is the the transfer frame and it's contents.
* The any reasonable [`EPB` options] may be set, but are optional.
  > Notably the [`epb_flags`] option has some useful information in it, but it may not be applicable


#### Interface Statistics Block

If present, the [Interface Statistics Block] is configured sensibly, the `Interface ID` field is set to the appropriate Bus ID (Usually `0` for a signal-bus capture), and the [statistics options] that are relevant are set. It is recommended that [`isb_starttime`] and [`isb_endtime`] are set if this block is present at all for any other statistical data (such as [`isb_ifrecv`]).


#### Options Definitions

We define one custom [PCAPNG] option block to attach to the standard Interface Description Block, this lets us store more detailed and comprehensive metadata about the bus and the capture rather than trying to fit into the existing option blocks.

It is defined below:

```
    0             0               1               2               3
    0             7               5               3               1
   ╭┴─────────────┴───────────────┴┬──────────────┴───────────────┴╮
 0 │            0x0BAD             │            0x0010             │
   ├───────────────────────────────┴───────────────────────────────┤
 4 │                          0x0000F578                           │
   ├───────────────────────────────┬───────────────────────────────┤
 8 │            0x0000             │           Bus Flags           │
   ├───────────────────────────────┴───────────────────────────────┤
12 │                                                               │
   │                            Reserved                           │
16 │                                                               │
   ╰───────────────────────────────────────────────────────────────╯

```
* `0x0BAD`
  > The [copyable custom option] code for [PCAPNG]
* `0x0010`
  > The length of the option payload + PEN
* `0x0000F578`
  > The [IANA] [Private Enterprise Number] for Shrine Maiden Heavy Industries (`62840`).
* `0x0000`
  > The Option Sub-ID for this option. Allows for multiple different Shrine Maiden Heavy Industries PCAPNG Option types.
* Bus Flags (`f16`)
  ```
    0         0                   1
    0         7                   5
  ╭─┴────┬────┴─┬────┬───┬───┬────┴─╮
  │ RCCC │ WWWW │ TT │ E │ P │ RRRR │
  ╰─┬──┬─┴────┬─┴──┬─┴─┬─┴─┬─┴────┬─╯
    │  │      │    │   │   │      ╰── Reserved Bits (must be 0)
    │  │      │    │   │   ╰───────── Paced Transfers Enabled/Disabled
    │  │      │    │   ╰───────────── Precompensation/Equalization Enabled/Disabled
    │  │      │    ╰───────────────── Electrical Type: HVD ( 00) /  SE ( 01) / LVD ( 10)
    │  │      │                                        MSE ( 11)
    │  │      ╰────────────────────── Data-path Width:   8 ( 00) /  16 ( 01) / 32 ( 10)
    │  ╰───────────────────────────── Bus Speed (MHz):   5 (000) /  10 (001) / 20 (010) ─╮
    │                                                   40 (011) / 80 (100) / 160 (101)  ├─ Bus Clock
    ╰──────────────────────────────── Bus data-rate:   SDR (  0) / DDR (  1)            ─╯
  ```
  > When this field is initialized to all `0`'s, it represents a valid SCSI-1 `HVD` bus, however, not all combinations of
  > flags are valid, for instance, setting `HVD` while also having set the bus speed to `160MHz DDR` is not a possible
  > SCSI bus.
  >
  > This field should be entirely ignored and discarded if any of the reserved bits are non-zero.

* Reserved (`bytes`)
  > 8 bytes of reserved space for future expansion, all bytes must be set to `0`

#### Multi-bus Captures

Multi-Bus captures are done by following the standard [PCAPNG] [block hierarchy], This likely should be done by only having capture streams for the target bus following the [Interface Description Block] for said bus, however, it seems that the PCAPNG file allows for interleaving, and as each [Enhanced Packet Block] and [Interface Statistics Block] have an `Interface ID` field, we use that as the SCSI Bus ID for the captures.

As such, when writing out a multi-bus capture, first write the [Section Header Block], as normal, followed by all `IDB`'s that are being captured in bus order (e.g. Bus 0 first, then 1, etc. ). Then, as long as the packet and statistics blocks have their `Interface ID` set to the proper originating bus ID, then it should all just work:tm:.

A resulting multi-bus capture file for 3 busses would then look roughly something like this:

```
╭───────────────────────────────╮
│     Section Header Block      │
├───────────────────────────────┤
│  Bus 00 Interface Desc Block  │ ─╮
├───────────────────────────────┤  │
│  Bus 01 Interface Desc Block  │  ├── IDBs in Bus ID order
├───────────────────────────────┤  │
│  Bus 02 Interface Desc Block  │ ─╯
├───────────────────────────────┤
│     Capture Block (Bus 00)    │ ─╮
├───────────────────────────────┤  │
│     Capture Block (Bus 02)    │  │
├───────────────────────────────┤  │
┊              ...              ┊  ├── EPBs can be out of order
├───────────────────────────────┤  │
│     Capture Block (Bus 01)    │  │
├───────────────────────────────┤  │
│     Capture Block (Bus 00)    │ ─╯
├───────────────────────────────┤
│  Bus 02 Interface Stat Block  │ ─╮
├───────────────────────────────┤  │
│  Bus 00 Interface Stat Block  │  ├── ISBs can also be in any order if any are present
├───────────────────────────────┤  │
│  Bus 01 Interface Stat Block  │ ─╯
╰───────────────────────────────╯
```

It is expected that multi-bus captures will be rare, as segmented SCSI busses are not common, but defining the behavior allows us to ensure that if it is ever wanted or done, we have the facilities to support it.

## Standardization

Once all the kinks have been worked out, it might be pertinent to offer this up to the [RFC] as an "official" link type if others might see use for it.

The process for which, seems to be unclear if it's to follow the IANA [RFC] process and/or the process on the [tcpdump] [`LINKTYPE_`] page under the section `HOW TO ASSIGN NEW VALUES`.

For now, we hijack a reserved User DLT value `DLT_USER7`, which is DLT value `154` (or `0x9A`), while there is a big fat warning on the [`LINKTYPE_`] page, we can't really do anything about that other than claim a reserved DLT value that is somewhere beyond the max DLT, but tools like [Wireshark] don't let us [re-map DLTs] to dissectors outside of the user DLT range.

## Supported Software

The following list is all known software that supports either emitting and/or consuming `LINKTYPE_PARALLEL_SCSI` framed SCSI captures. If you have added support to your software, please [let us know]!

### Capture

The following software supports emitting SCSI captures with `LINKTYPE_PARALLEL_SCSI` framing, either as raw framed data, or as a [pcap] or [pcapng] file.

* [Squishy]
  * SCSI Analyzer can emit [pcapng] files with `LINKTYPE_PARALLEL_SCSI` framing
  * [`scsidump`], a wireshark [extcap] interface can do the same

### Dissection

The following software supports consuming and dissecting SCSI captures with `LINKTYPE_PARALLEL_SCSI` framing.

* [wireshark-scsi]
   * SCSI Framer and higher-level dissectors as a part of this repo to add support to [Wireshark]

[tcpdump]: https://www.tcpdump.org/
[`LINKTYPE_`]: https://www.tcpdump.org/linktypes.html
[Transfer Frames]: #transaction-frame
[Fibre Channel]: https://wiki.wireshark.org/FibreChannel
[iSCSI]: https://wiki.wireshark.org/iSCSI
[something else]: https://wiki.wireshark.org/Small_Computer_System_Interface
[network order]: https://www.rfc-editor.org/rfc/rfc1700.html#:~:text=Standards%22%20(STD%201).-,Data%20Notations,-The%20convention%20in
[multi-bus capture]: #Multi-bus-Captures
[ancillary information]: #Frame-Capture-Storage
[PCAPNG Block alignment requirements]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#name-alignment
[Interface Description Block]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section_idb
[`if_name`]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.2-11
[`if_description`]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.2-13
[`if_hardware`]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.2-37
[Interface Statistics Block]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#name-interface-statistics-block
[statistics options]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.6-6
[`isb_starttime`]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.6-8
[`isb_endtime`]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.6-10
[`isb_ifrecv`]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.6-12
[Option Blocks]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#name-options
[block hierarchy]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-3.3
[Enhanced Packet Blocks]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#name-enhanced-packet-block
[`EPB` options]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.3-7
[`epb_flags`]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.3-9
[Bus Metadata]: #Options-Definitions
[Section Header Block]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#name-section-header-block
[copyable custom option]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-3.5.1-4.1.3
[IANA]: https://www.iana.org/
[Private Enterprise Number]: https://www.rfc-editor.org/rfc/rfc9371.html
[Standardization]: #standardization
[RFC]: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcaplinktype/
[Wireshark]: https://www.wireshark.org/
[re-map DLTs]: https://www.wireshark.org/docs/wsug_html_chunked/ChUserDLTsSection.html
[pcap]: https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html
[pcapng]: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/02/
[Squishy]: https://docs.scsi.moe/
[`scsidump`]: https://docs.scsi.moe/extra.html#scsidump
[extcap]: https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
[wireshark-scsi]: https://github.com/squishy-scsi/wireshark-scsi
[let us know]: https://github.com/squishy-scsi/wireshark-scsi/issues/new
[`examples`]: ../examples/
