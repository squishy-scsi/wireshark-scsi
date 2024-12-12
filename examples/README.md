# `LINKTYPE_PARALLEL_SCSI` Example PCAPs

This directory contains example capture files that follow the format as specified in[`LINKTYPE_PARALLEL_SCSI`].

At the moment all the the frame data is filled with random garbage, but this will change soon.

* [`combined-frames.pcapng`](./combined-frames.pcapng)
  > A PCAPNG file with a one frame for each
* [`multi-bus.pcapng`](./multi-bus.pcapng)
  > A Multi-bus PCAPNG with 128 frames assigned to one of 3 busses at random
* [`arbitration.pcapng`](./arbitration.pcapng)
  > A PCAPNG file with a single frame of type `ARBITRATION`
* [`bus_condition.pcapng`](./bus_condition.pcapng)
  > A PCAPNG file with a single frame of type `BUS_CONDITION`
* [`command.pcapng`](./command.pcapng)
  > A PCAPNG file with a single frame of type `COMMAND`
* [`data_in.pcapng`](./data_in.pcapng)
  > A PCAPNG file with a single frame of type `DATA_INT`
* [`data_out.pcapng`](./data_out.pcapng)
  > A PCAPNG file with a single frame of type `DATA_OUT`
* [`information_unit.pcapng`](./information_unit.pcapng)
  > A PCAPNG file with a single frame of type `INFORMATION_UNIT`
* [`invalid.pcapng`](./invalid.pcapng)
  > A PCAPNG file with a single frame of type `INVALID`
* [`message.pcapng`](./message.pcapng)
  > A PCAPNG file with a single frame of type `MESSAGE`
* [`combined-frames.pcapng`](./combined-frames.pcapng)
  > A PCAPNG file with one of each frame type.


[`LINKTYPE_PARALLEL_SCSI`]: ../docs/LINKTYPE_PARALLEL_SCSI.md
