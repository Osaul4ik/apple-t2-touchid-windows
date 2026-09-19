// SPDX-License-Identifier: GPL-2.0-only
// Queue.cpp - WBDI IOCTL dispatch (skeleton: attributes + sensor status only).
#include "Internal.h"

// ---------------------------------------------------------------------------
// VERIFY AGAINST THE WDK HEADERS (winbio_types.h / winbio_ioctl.h).
// This skeleton was written without a WDK at hand. Every WinBio type/constant
// name below is from memory of the WBDI docs / WudfBioUsbSample; the aliases
// are grouped here so that a wrong name is a one-line fix.
// ---------------------------------------------------------------------------
using T2BioSensorAttributes = WINBIO_SENSOR_ATTRIBUTES;   // out of GET_ATTRIBUTES
using T2BioSensorStatusOut  = WINBIO_SENSOR_STATUS_DATA;  // out of GET_SENSOR_STATUS (name UNSURE)

namespace {

// Placeholder identity strings shown by WinBio / Settings.
constexpr wchar_t kManufacturer[] = L"Osaul4ik";
constexpr wchar_t kModel[]        = L"Apple T2 Touch ID (SEP)";
constexpr wchar_t kSerial[]       = L"T2-0001";

void FillAttributes(T2BioSensorAttributes& a)
{
    RtlZeroMemory(&a, sizeof(a));
    a.PayloadSize   = sizeof(a);
    a.WinBioHresult = S_OK;
    a.WinBioVersion.MajorVersion = WINBIO_WBDI_MAJOR_VERSION;
    a.WinBioVersion.MinorVersion = WINBIO_WBDI_MINOR_VERSION;

    a.SensorType    = WINBIO_TYPE_FINGERPRINT;
    a.SensorSubType = WINBIO_FP_SENSOR_SUBTYPE_TOUCH;

    // Sensor only: matching happens in the T2 SEP, and our "engine" is a thin
    // matchedUuid comparison (design doc 7.4), not a WBDI-visible capability.
    a.Capabilities  = WINBIO_CAPABILITY_SENSOR;

    (void)StringCchCopyW(a.ManufacturerName, ARRAYSIZE(a.ManufacturerName), kManufacturer);
    (void)StringCchCopyW(a.ModelName,        ARRAYSIZE(a.ModelName),        kModel);
    (void)StringCchCopyW(a.SerialNumber,     ARRAYSIZE(a.SerialNumber),     kSerial);
    a.FirmwareVersion.MajorVersion = 0;
    a.FirmwareVersion.MinorVersion = 1;

    // PLACEHOLDER: real data format is a vendor BIR (design doc 5:
    // VerifyOutcome + matchedUuid, no raw fingerprint), which needs its own
    // registered format owner. ANSI-381 is here only so the entry is well-formed
    // for the "does WinBio see the device" gate.
    a.SupportedFormatEntries = 1;
    a.SupportedFormat[0].Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    a.SupportedFormat[0].Type  = WINBIO_ANSI_381_FORMAT_TYPE;
}

void HandleGetAttributes(_In_ WDFREQUEST Request)
{
    T2BioSensorAttributes* out = nullptr;
    const NTSTATUS status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(T2BioSensorAttributes), reinterpret_cast<PVOID*>(&out), nullptr);
    if (!NT_SUCCESS(status)) {
        // TODO(verify): WBDI's "buffer too small" convention (PayloadSize /
        // Information semantics) - compare with WudfBioUsbSample Device.cpp.
        WdfRequestCompleteWithInformation(Request, status, sizeof(T2BioSensorAttributes));
        return;
    }
    FillAttributes(*out);
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(T2BioSensorAttributes));
}

void HandleGetSensorStatus(_In_ WDFREQUEST Request)
{
    T2BioSensorStatusOut* out = nullptr;
    const NTSTATUS status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(T2BioSensorStatusOut), reinterpret_cast<PVOID*>(&out), nullptr);
    if (!NT_SUCCESS(status)) {
        WdfRequestCompleteWithInformation(Request, status, sizeof(T2BioSensorStatusOut));
        return;
    }
    RtlZeroMemory(out, sizeof(*out));
    out->PayloadSize   = sizeof(*out);
    out->WinBioHresult = S_OK;
    // Always READY for the skeleton. Real logic (design doc 3) later:
    // open GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT, IOCTL_T2_GET_STATUS, and
    // Global\T2SepReady from T2SepBootstrap.
    out->SensorStatus  = WINBIO_SENSOR_READY;
    out->VendorStatus  = 0;
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*out));
}

} // namespace

extern "C" VOID T2BioEvtIoDeviceControl(_In_ WDFQUEUE Queue,
                                        _In_ WDFREQUEST Request,
                                        _In_ size_t OutputBufferLength,
                                        _In_ size_t InputBufferLength,
                                        _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    T2BioLog("IOCTL 0x%08x", IoControlCode);

    switch (IoControlCode) {
    case IOCTL_BIOMETRIC_GET_ATTRIBUTES:
        HandleGetAttributes(Request);
        return;

    case IOCTL_BIOMETRIC_GET_SENSOR_STATUS:
        HandleGetSensorStatus(Request);
        return;

    case IOCTL_BIOMETRIC_RESET:
        // No sensor state to reset yet.
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;

    case IOCTL_BIOMETRIC_CAPTURE_DATA:
        // Wired to VerificationEngine::Verify() in the next step (design doc 3/9.4).
        WdfRequestComplete(Request, STATUS_NOT_SUPPORTED);
        return;

    default:
        // IOCTL_BIOMETRIC_CALIBRATE is never sent while status never says
        // "not calibrated"; anything else is unsupported.
        WdfRequestComplete(Request, STATUS_NOT_SUPPORTED);
        return;
    }
}
