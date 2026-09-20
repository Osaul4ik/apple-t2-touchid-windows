// SPDX-License-Identifier: GPL-2.0-only
// WbdiBir.h - wraps / unwraps the vendor sample payload in a WINBIO_BIR.
//
// Shared by the UMDF driver (builds the BIR it returns as
// WINBIO_CAPTURE_DATA::CaptureData) and the WBF engine adapter (parses it in
// AcceptSampleData). Layout, per winbio_types.h:
//
//   [WINBIO_BIR: 4 x {Size, Offset}] [WINBIO_BIR_HEADER] [pad] [vendor payload] [pad]
//
// * StandardDataBlock is empty: winbio_types.h reserves it for ANSI-381 image
//   data, and this project has no fingerprint image (README: does not store or
//   transmit raw biometric data). BiometricDataFormat/ProductId are therefore
//   "no owner/type available", as the header documents for that case.
// * VendorDataBlock carries t2::biometrickit::T2VendorSamplePayload verbatim.
// * All blocks are 8-byte aligned (WINBIO_BIR_ALIGN_SIZE).
//
// The include needs windows.h + winbio_types.h before it (both consumers have
// them), and nothing else: no BridgeXPC / VerificationEngine dependency.
#pragma once
#include "../../protocol/BiometricKit/VendorWire.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace t2::wbdi {

inline size_t Align8(size_t n)
{
    return (n + (WINBIO_BIR_ALIGN_SIZE - 1)) & ~static_cast<size_t>(WINBIO_BIR_ALIGN_SIZE - 1);
}

// Size of the BIR BuildVendorBir() produces for a payload of `payloadSize`.
inline size_t VendorBirSize(size_t payloadSize)
{
    const size_t vendorOffset = Align8(sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER));
    return Align8(vendorOffset + payloadSize);
}

inline std::vector<uint8_t> BuildVendorBir(WINBIO_BIR_PURPOSE purpose,
                                           WINBIO_BIR_DATA_FLAGS flags,
                                           const std::vector<uint8_t>& payload)
{
    const size_t headerOffset = sizeof(WINBIO_BIR);
    const size_t vendorOffset = Align8(headerOffset + sizeof(WINBIO_BIR_HEADER));
    std::vector<uint8_t> out(VendorBirSize(payload.size()), 0);

    WINBIO_BIR bir{};
    bir.HeaderBlock.Size   = static_cast<ULONG>(sizeof(WINBIO_BIR_HEADER));
    bir.HeaderBlock.Offset = static_cast<ULONG>(headerOffset);
    bir.VendorDataBlock.Size   = static_cast<ULONG>(payload.size());
    bir.VendorDataBlock.Offset = static_cast<ULONG>(vendorOffset);
    // StandardDataBlock / SignatureBlock stay {0,0}.

    WINBIO_BIR_HEADER header{};
    header.ValidFields = static_cast<USHORT>(
        WINBIO_BIR_FIELD_CBEFF_HEADER_VERSION | WINBIO_BIR_FIELD_PATRON_HEADER_VERSION |
        WINBIO_BIR_FIELD_BIOMETRIC_TYPE | WINBIO_BIR_FIELD_BIOMETRIC_PURPOSE |
        WINBIO_BIR_FIELD_QUALITY);
    header.HeaderVersion       = WINBIO_CBEFF_HEADER_VERSION;
    header.PatronHeaderVersion = WINBIO_PATRON_HEADER_VERSION;
    // winbio_types.h: WINBIO_DATA_FLAG_OPTION_MASK_PRESENT is "always '1'" in a
    // BIR header. WBF's capture request carries only RAW (0x20), so echoing it
    // verbatim produced a header that violates that rule.
    header.DataFlags   = static_cast<WINBIO_BIR_DATA_FLAGS>(flags | WINBIO_DATA_FLAG_OPTION_MASK_PRESENT);
    header.Type        = WINBIO_TYPE_FINGERPRINT;
    header.Purpose     = purpose;
    header.DataQuality = WINBIO_DATA_QUALITY_NOT_SUPPORTED;

    std::memcpy(out.data(), &bir, sizeof(bir));
    std::memcpy(out.data() + headerOffset, &header, sizeof(header));
    if (!payload.empty()) {
        std::memcpy(out.data() + vendorOffset, payload.data(), payload.size());
    }
    return out;
}

struct ParsedVendorBir {
    const uint8_t*        Payload = nullptr;   // points into the caller's buffer
    size_t                PayloadSize = 0;
    WINBIO_BIR_PURPOSE    Purpose = 0;         // from the BIR header
    WINBIO_BIR_DATA_FLAGS Flags = 0;
};

inline bool BlockInRange(const WINBIO_BIR_DATA& b, size_t total)
{
    const size_t off = static_cast<size_t>(b.Offset);
    const size_t len = static_cast<size_t>(b.Size);
    return off <= total && len <= total - off;
}

// Strict: any structural surprise returns false and leaves *out untouched.
inline bool ParseVendorBir(const void* buffer, size_t size, ParsedVendorBir* out)
{
    if (buffer == nullptr || out == nullptr || size < sizeof(WINBIO_BIR)) {
        return false;
    }
    WINBIO_BIR bir{};
    std::memcpy(&bir, buffer, sizeof(bir));

    if (!BlockInRange(bir.HeaderBlock, size) || !BlockInRange(bir.VendorDataBlock, size) ||
        !BlockInRange(bir.StandardDataBlock, size) || !BlockInRange(bir.SignatureBlock, size)) {
        return false;
    }
    if (bir.HeaderBlock.Size < sizeof(WINBIO_BIR_HEADER) || bir.VendorDataBlock.Size == 0) {
        return false;
    }
    // This project never produces a standard (ANSI-381) block or a signature.
    if (bir.StandardDataBlock.Size != 0 || bir.SignatureBlock.Size != 0) {
        return false;
    }

    const uint8_t* base = static_cast<const uint8_t*>(buffer);
    WINBIO_BIR_HEADER header{};
    std::memcpy(&header, base + bir.HeaderBlock.Offset, sizeof(header));
    if ((header.ValidFields & WINBIO_BIR_FIELD_NEVER_VALID) != 0) {
        return false;   // winbio_types.h: such a BIR is malformed
    }

    out->Payload     = base + bir.VendorDataBlock.Offset;
    out->PayloadSize = static_cast<size_t>(bir.VendorDataBlock.Size);
    out->Purpose     = header.Purpose;
    out->Flags       = header.DataFlags;
    return true;
}

} // namespace t2::wbdi