// SPDX-License-Identifier: GPL-2.0-only
// Queue.cpp - WBDI IOCTL dispatch (skeleton: attributes + sensor status only).
#include "Internal.h"

// ---------------------------------------------------------------------------
// Type names below were checked against winbio_ioctl.h / winbio_types.h of
// Windows Kits 10.0.26100.0 (the CI "Dump WinBio WBDI headers" artifact).
// ---------------------------------------------------------------------------
using T2BioSensorAttributes = WINBIO_SENSOR_ATTRIBUTES;   // out of GET_ATTRIBUTES

// GET_SENSOR_STATUS OUT payload is WINBIO_DIAGNOSTICS (winbio_ioctl.h, Windows
// Kits 10.0.26100.0): { DWORD PayloadSize; HRESULT WinBioHresult;
// WINBIO_SENSOR_STATUS SensorStatus; WINBIO_DATA VendorDiagnostics; }.
// The former local mirror (16 bytes) was wrong: the real struct also carries
// the WINBIO_DATA tail, so PayloadSize has to be sizeof(WINBIO_DIAGNOSTICS).
using T2BioDiagnostics = WINBIO_DIAGNOSTICS;

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

// WBDI size-probe convention (Microsoft WudfBioUsbSample, Device.cpp
// OnGetAttributes / OnGetSensorStatus; the sample was removed from
// Windows-driver-samples master in 2024, last present in c73af47~1):
//   - output buffer missing or smaller than a DWORD: fail with E_INVALIDARG
//     semantics (here STATUS_INVALID_PARAMETER),
//   - output buffer smaller than the payload: write the REQUIRED size into
//     PayloadSize, complete with SUCCESS and Information = sizeof(DWORD);
//     the caller then re-issues with a buffer of PayloadSize bytes.
// The previous code asked WdfRequestRetrieveOutputBuffer for the full payload
// size up front, so a small-buffer probe would have failed with
// STATUS_BUFFER_TOO_SMALL instead of reporting the required size.
template <typename Payload>
Payload* RetrieveProbedPayload(_In_ WDFREQUEST Request, _Out_ bool* fitsFully)
{
    *fitsFully = false;
    Payload* out = nullptr;
    size_t outLen = 0;
    const NTSTATUS status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(DWORD), reinterpret_cast<PVOID*>(&out), &outLen);
    if (!NT_SUCCESS(status) || out == nullptr) {
        WdfRequestComplete(Request, NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status);
        return nullptr;
    }
    if (outLen < sizeof(Payload)) {
        out->PayloadSize = static_cast<DWORD>(sizeof(Payload)); // required size, first member of both payloads
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return nullptr;
    }
    *fitsFully = true;
    return out;
}

void HandleGetAttributes(_In_ WDFREQUEST Request)
{
    bool fits = false;
    T2BioSensorAttributes* out = RetrieveProbedPayload<T2BioSensorAttributes>(Request, &fits);
    if (!fits) {
        return; // already completed (error or size probe)
    }
    FillAttributes(*out);
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, out->PayloadSize);
}

void HandleGetSensorStatus(_In_ WDFREQUEST Request)
{
    bool fits = false;
    T2BioDiagnostics* out = RetrieveProbedPayload<T2BioDiagnostics>(Request, &fits);
    if (!fits) {
        return;
    }
    RtlZeroMemory(out, sizeof(*out));
    out->PayloadSize   = sizeof(*out);
    out->WinBioHresult = S_OK;
    // Always READY for the skeleton. Real logic (design doc 3) later:
    // open GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT, IOCTL_T2_GET_STATUS, and
    // Global\T2SepReady from T2SepBootstrap.
    out->SensorStatus  = WINBIO_SENSOR_READY;
    out->VendorDiagnostics.Size = 0;
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, out->PayloadSize);
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