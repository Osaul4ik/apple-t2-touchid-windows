# Why the adapter transmitted and never received

## The symptom

The adapter enumerated, registered, bound to TCP/IP and looked entirely
healthy:

```
SentBroadcastPackets     : 46
SentMulticastPackets     : 300
SentBytes                : 36101
ReceivedBytes            : 0
ReceivedUnicastPackets   : 0
ReceivedMulticastPackets : 0
ReceivedPacketErrors     : 0
```

Every counter on the receive side was zero — not errors, not discards,
*zero*. Windows sent its own router solicitations and multicast listener
reports quite happily, and the BridgeOS peer stayed permanently
`Unreachable` in the neighbour table, because not one neighbour
advertisement ever came back.

Zero received **bytes** with zero received **errors** is the important
detail. It rules out the parser, the NTB geometry, the pipe, the packet
filter in this driver, and NDIS: all of those would have produced
non-zero counters somewhere. The bulk-IN endpoint simply never delivered
anything, which means the device was never sending.

## The cause

CDC ECM 1.2 §6.2.4 defines `SET_ETHERNET_PACKET_FILTER`, and NCM 1.0
inherits it unchanged. **The device forwards nothing to the host until
the host sets a filter, and it resets the filter to zero on every
`SET_CONFIGURATION` and `SET_INTERFACE`.** This driver never issued the
request. It issued `GET_NTB_PARAMETERS`, `SET_NTB_FORMAT`,
`SET_NTB_INPUT_SIZE` and `SET_INTERFACE(alt 1)` — everything needed to
*transmit* — and then waited for frames the T2 had been told not to send.

That is also exactly why the Linux reference setup works. The
`t2-touchid-linux` project uses the stock `cdc_ncm` driver, and
`usbnet` issues `USB_CDC_SET_ETHERNET_PACKET_FILTER` from
`ndo_set_rx_mode` as soon as the interface goes up
(`drivers/net/usb/cdc_ether.c`, `usbnet_cdc_update_filter`, wired up by
`cdc_ncm` via `.set_rx_mode`). Nothing else about the two bring-up
sequences differs in a way that could produce this.

## The fix

`T2NcmSetEthernetPacketFilter` in `NcmProtocol.c`: class request `0x43`,
`bmRequestType` `0x21`, `wValue` = the filter bitmap, `wIndex` = the
control interface number, no data stage.

It is sent from three places, and the ordering constraint is the same
everywhere — **after** the alt-1 switch, never before, because
`SET_INTERFACE` is what clears it:

1. `T2NcmPowerArmHardware`, immediately after
   `T2NcmUsbActivateDataInterface`. This covers first bring-up and every
   resume from a low-power state.
2. `MiniportRestart`, if the device is not currently known to be holding
   a filter.
3. The `OID_GEN_CURRENT_PACKET_FILTER` and `OID_802_3_MULTICAST_LIST`
   set handlers, so a change of heart by the stack reaches the device.

`T2NcmUsbDeactivateDataInterface` clears `CdcPacketFilterApplied`, so
nothing mistakes a stale value for a filter the device is actually
holding.

`MiniportOidRequest` may run above `PASSIVE_LEVEL` and control transfers
may not, so `T2NcmRequestPacketFilterUpdate` applies the change inline at
`PASSIVE_LEVEL` and otherwise defers it to a work item. It is never
simply dropped — a filter update that silently never reaches the device
is the precise bug this whole path exists to fix.

## The station address, and why PROMISCUOUS is in the filter

Real REV_0201 units report an empty USB string table. There is no
`iMACAddress` to read, so the adapter runs on a deterministic
locally-administered address derived from the ContainerID
(`T2NcmEnsureMacAddress`). Linux ends up in the same place — `cdc_ncm`
falls back to a random address when it cannot read one — so this is not
itself a defect, and it is not what broke reception.

It does have one consequence worth handling. The device was never told
which unicast address belongs to the host, so a `DIRECTED`-only filter is
a filter against an address the device does not know, and frames the T2
addresses to whatever it *thinks* the host is would be dropped on the
device side. Two mitigations, both scoped to exactly this case:

* `T2NcmNdisFilterToCdcFilter` adds `PROMISCUOUS` to the CDC filter when
  the station address did not come from the device. On a point-to-point
  USB link with exactly one peer this costs nothing.
* `T2NcmRxAcceptsFrame` accepts unicast addressed elsewhere under the
  same condition, so the software filter does not undo what the CDC
  filter just allowed.

When `MacAddressIsPermanent` is true, both relaxations are off and normal
directed filtering applies.

## Notification endpoint

`T2NcmCtrl.sys` now drains MI_00's interrupt IN endpoint instead of
leaving it alone. The device does not know nobody is listening: a CDC
function holding an undelivered `NETWORK_CONNECTION` or
`CONNECTION_SPEED_CHANGE` notification can sit on it, and some
implementations gate the data path behind having delivered it. The
notifications are logged and discarded — link state for this adapter is
still "the USB interface is configured", and inventing a link-state
policy from notifications nobody has yet observed on this hardware would
be guessing.

## Telling the three silences apart next time

`IOCTL_T2NCM_GET_STATUS` gained the fields that make this diagnosable
without a USB capture:

| Reading | Meaning |
| --- | --- |
| `CdcPacketFilterApplied` false, or `CdcPacketFilter` zero | The device has been told to forward nothing. RX will be exactly zero. |
| `RxNtbsReceived` / `RxFramesParsed` zero | Nothing is arriving on the bulk-IN pipe at all. |
| `RxFramesParsed` high, `RxFramesFiltered` high | Frames arrive and this driver throws them away — packet filter or station-address mismatch. |
| `RxFramesParsed` high, `RxFramesIndicated` high | Frames reach NDIS; look above the miniport. |

## What to expect on the next hardware run

Once frames flow, the peer address should be **discovered**, not
computed. `t2touchid network` derives a candidate from the host's own MAC
by flipping the U/L bit, which is only ever a guess — and with a
generated station address it is a guess about an address nobody has. Ping
`ff02::1` on the interface and read `netsh interface ipv6 show neighbors`
instead; whatever answers is the real BridgeOS link-local, and that is
what belongs in `--host` (the same value Linux keeps in
`T2_TOUCHID_HOST`).

None of this has been built with a WDK or run against hardware here.