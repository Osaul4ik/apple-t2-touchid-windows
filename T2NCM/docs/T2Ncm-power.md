# T2Ncm.sys — inverting power management

## Why this changed

The previous design made T2Ncm.sys a KMDF function driver that owned the
PnP and power policy for MI_01: `EvtDevicePrepareHardware` created the
USB target, `EvtDeviceD0Entry` negotiated the NCM control plane and
started the receive engine, `EvtDeviceD0Exit` stopped it. An NDIS
miniport was going to be attached to the side of that.

For a network adapter that is backwards, and Microsoft's guidance for
NDIS miniports says so directly:

* **NDIS is the power policy owner of a miniport adapter.** Not the
  driver, and not KMDF.
* **NDIS pauses the miniport before every low-power transition** and
  restarts it after the return to D0. The ordering is guaranteed:

  ```
  going down:   MiniportPause          ->  OID_PNP_SET_POWER(Dx)
  coming up:    OID_PNP_SET_POWER(D0)  ->  MiniportRestart
  ```

* Therefore the **data path** belongs to Pause/Restart and the
  **hardware D-state** belongs to `OID_PNP_SET_POWER` — never to a
  driver-private D0Entry/D0Exit running on its own schedule underneath
  NDIS.

So the direction of control is inverted. NDIS drives this driver; this
driver drives KMDF.

## How the inversion is enforced, not just intended

`DriverEntry` creates the WDF driver with
`WdfDriverInitNoDispatchOverride` and no `EvtDeviceAdd`, then calls
`NdisMRegisterMiniportDriver`. KMDF never takes the dispatch table, never
gets an AddDevice, and never sees a PnP or power IRP.

Each adapter's WDFDEVICE is created with `WdfDeviceMiniportCreate` over
the device objects `NdisMGetDeviceProperty` returns. Such a device **is
not a power policy owner and has no PnP/power callbacks at all** — there
is no `EvtDeviceD0Entry` to write even by accident. The invariant is
structural rather than a convention someone has to remember.

## Callback map

| Old (KMDF owned power) | New (NDIS owns power) |
| --- | --- |
| `EvtDevicePrepareHardware` + bring-up half of `EvtDeviceD0Entry` | `MiniportInitializeEx` |
| `EvtDeviceD0Entry` — "start RX" | `MiniportRestart` |
| `EvtDeviceD0Exit` — "stop RX" | `MiniportPause` |
| `EvtDeviceD0Exit` — "go to Dx" | `OID_PNP_SET_POWER` (`Power.c`) |
| `EvtDeviceReleaseHardware` | `MiniportHaltEx` |
| `EvtDeviceSelfManagedIo*` | *(nothing — NDIS covers it)* |
| `WdfDeviceCreateDeviceInterface` + I/O queue | `NdisMRegisterDeviceEx` (`\\.\T2Ncm`) |
| `g_T2NcmStubRole` (MI_00 role in the same binary) | separate binary, `CtrlStub.c` → `T2NcmCtrl.sys` |

## What each piece is now allowed to do

**`MiniportInitializeEx`** wraps the NDIS-built stack in a WDFDEVICE,
creates the USB target, reads the station address once, brings the NCM
control plane up, switches MI_01 to alt 1, and registers the adapter's
attributes. It then **leaves the adapter paused**. Initialization no
longer starts the data path — that single change is the inversion in
practice.

**`MiniportRestart`** is the only thing that sets `DataPathRunning` and
starts the bulk-IN reader. It refuses if the recorded power state is not
D0 or if the bulk pipes are missing, because either would mean the model
has been broken somewhere upstream and a loud failure beats silent USB
errors.

**`MiniportPause`** closes the gate first, then stops the reader, then
drains. Both orders of the first two steps "work"; only this one closes
the window where the reader has stopped but an in-flight completion still
indicates a frame at a paused adapter. The drain waits for indicated NBLs
to be returned and for submitted bulk-OUT writes to complete, bounded at
five seconds — a pause that hung would hang the whole system power
transition, so a leaked reference is logged and stepped over rather than
waited on forever.

**`Power.c`** moves hardware between states and nothing else. On Dx it
parks MI_01 on alt 0 (its zero-endpoint idle setting) and drops the
cached pipe handles; on D0 it re-runs the control-plane negotiation and
re-selects alt 1, and deliberately does **not** start the receive engine —
`MiniportRestart` follows a moment later and owns that.

A D0 transition is never failed for a hardware reason. An adapter that
comes back without a working control plane is recoverable by a
disable/enable or a replug; a wedged S3 resume is not. The lifecycle state
stays honest (it falls back to `UsbReady` rather than claiming
`NcmReady`) and the failure is logged.

The station address is read exactly once, at first initialization, and is
deliberately not re-read on resume. A NIC whose MAC changes across S3
would be a worse failure than a stale one.

## Power management capabilities

The adapter registers `NDIS_PM_CAPABILITIES` with everything zeroed and
the three `Min*WakeUp` members left at `NdisDeviceStateUnspecified` —
which is how a miniport states that it cannot wake the system from any
D-state. That is the truth for this device: nothing in the T2's NCM
function descriptors advertises remote wake. Saying so explicitly is what
lets NDIS still place the adapter in Dx instead of treating it as
PM-unaware.

`NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND` is set for the same reason.
Without it NDIS halts the miniport on every suspend, tearing down the USB
target and the WDFDEVICE and rebuilding them on resume; with it, a
suspend is exactly the Pause → Dx → D0 → Restart sequence `Power.c` is
written against. `NDIS_MINIPORT_ATTRIBUTES_NDIS_WDM` is set because this
driver reaches a lower driver (the USB stack, through KMDF) rather than
touching hardware registers itself.

## Observing it from user mode

`IOCTL_T2NCM_GET_STATUS` reports the two halves of the model separately
and on purpose:

* `PowerState` — what NDIS last said via `OID_PNP_SET_POWER`.
* `DataPathRunning` — what `MiniportPause`/`MiniportRestart` last set.
* `OutstandingRxNbls` / `OutstandingTxRequests` — what a pause has to
  drain.

A regression in the inversion shows up as those disagreeing. A running
data path at a non-D0 power state means frames are being pushed at a
suspended device; non-zero drain counters while `DataPathRunning` is
false means a pause returned without actually draining.

## Known gaps

* Nothing here has been built with a real WDK or run against real
  hardware — there is neither in the environment this was written in.
* TX sends one NTB per `NET_BUFFER`, single datagram each. Batching
  several datagrams into one NTB would cut per-frame USB overhead, but it
  also makes one failed write drop several frames and needs a per-NTB
  refcount across NBLs. Worth doing only once there is throughput data
  from hardware to justify it.
* RX copies each datagram into a fresh NBL rather than indicating an MDL
  over the reader's own buffer. The reader re-arms as soon as its
  completion returns, so zero-copy would mean not re-arming until the
  protocol stack was finished with the frame — a worse trade than one
  memcpy per frame at 480 Mbit/s.
* Only the `NCM0` datagram-pointer variant is handled, in both
  directions. The CRC (`NCM1`) and IPS variants are not, because there is
  no capture evidence the T2 uses them and this driver does not guess
  wire formats.
* `MiniportCheckForHangEx` is not implemented. A wedged NCM endpoint looks
  exactly like an idle one from here, so a hang check could only guess.