# Notice

This project is licensed under the GNU General Public License version 2
only (`GPL-2.0-only`). See `LICENSE`.

## Attribution

Protocol facts used throughout this codebase (T2 SEP PCI vendor/device ID,
mailbox MMIO register offsets, endpoint numbers, AppleKeyStore opcodes,
control-message layout, timing constants) were extracted from direct
analysis of:

- github.com/jmurth1234/t2-touchid-linux (GPL-2.0-only)

Source-level comments marked `VERIFIED FROM SOURCE` throughout this
codebase (e.g. `driver/T2TouchIdTransport/driver.h`,
`driver/T2TouchIdTransport/public.h`) identify values taken from that
reference. No algorithmic logic, comment text, or verbatim code from that
project is reproduced here; all implementation code in this repository
(KMDF driver, protocol libraries, tools) is written independently for the
Windows platform and its APIs (WDF/KMDF, Win32 `DeviceIoControl`, C++),
which necessarily differ structurally from the Linux kernel/PCI driver
model the reference project targets.
