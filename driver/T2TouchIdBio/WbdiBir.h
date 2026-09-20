// SPDX-License-Identifier: GPL-2.0-only
// WbdiBir.h - wraps / unwraps the vendor sample payload in a WINBIO_BIR.
//
// Shared by the UMDF driver (builds the BIR it returns as
// WINBIO_CAPTURE_DATA::CaptureData) and the WBF engine adapter (parses it in
// AcceptSampleData). Layout, per winbio_types.h:
//
//   [WINBIO_BIR: 4 x {Size, Offset}] [WINBIO_BIR_HEADER] [pad]
//   [ANSI-381 placeholder block] [pad] [vendor payload] [pad]
//
// * StandardDataBlock carries a PLACEHOLDER ANSI-381 record (a small, constant,
//   mid-gray image - see BuildPlaceholderAnsi381). There is no real fingerprint
//   image in this project (README: does not store or transmit raw biometric
//   data). The block exists only because WBF asks the sensor for a RAW sample in
//   the ANSI-381 format the sensor advertises, and WBF's own sensor adapter
//   hands nothing on to the engine when that block is missing. It is NEVER
//   trusted: the engine adapter decides only from the vendor payload.
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

// Placeholder image geometry: 16x16, 8 bpp, uncompressed, constant gray.
constexpr USHORT kPlaceholderImageSide  = 16;
constexpr size_t kPlaceholderImageBytes = static_cast<size_t>(kPlaceholderImageSide) * kPlaceholderImageSide;
constexpr UCHAR  kPlaceholderImageGray  = 0x80;

inline size_t PlaceholderAnsi381Size()
{
    return sizeof(WINBIO_BDB_ANSI_381_HEADER) + sizeof(WINBIO_BDB_ANSI_381_RECORD) + kPlaceholderImageBytes;
}

// A structurally valid ANSI INCITS 381-2004 block (one record) around a constant
// image. Contains no biometric information.
inline std::vector<uint8_t> BuildPlaceholderAnsi381()
{
    std::vector<uint8_t> out(PlaceholderAnsi381Size(), 0);

    WINBIO_BDB_ANSI_381_HEADER hdr{};
    hdr.RecordLength             = static_cast<ULONG64>(out.size());
    hdr.FormatIdentifier         = 0x46495200;   // 'F' 'I' 'R' 0
    hdr.VersionNumber            = 0x30313000;   // '0' '1' '0' 0
    hdr.ProductId.Owner          = WINBIO_NO_FORMAT_OWNER_AVAILABLE;
    hdr.ProductId.Type           = WINBIO_NO_FORMAT_TYPE_AVAILABLE;
    hdr.CaptureDeviceId          = 0;
    hdr.ImageAcquisitionLevel    = WINBIO_ANSI_381_IMG_ACQ_LEVEL_31;
    hdr.HorizontalScanResolution = 500;
    hdr.VerticalScanResolution   = 500;
    hdr.HorizontalImageResolution = 500;
    hdr.VerticalImageResolution  = 500;
    hdr.ElementCount             = 1;
    hdr.ScaleUnits               = WINBIO_ANSI_381_PIXELS_PER_INCH;
    hdr.PixelDepth               = 8;
    hdr.ImageCompressionAlg      = WINBIO_ANSI_381_IMG_UNCOMPRESSED;

    WINBIO_BDB_ANSI_381_RECORD rec{};
    rec.BlockLength         = static_cast<ULONG>(sizeof(rec) + kPlaceholderImageBytes);
    rec.HorizontalLineLength = kPlaceholderImageSide;
    rec.VerticalLineLength  = kPlaceholderImageSide;
    rec.Position            = WINBIO_ANSI_381_POS_UNKNOWN;
    rec.CountOfViews        = 1;
    rec.ViewNumber          = 1;
    rec.ImageQuality        = 0xFE;   // "reserved - must be 254"
    rec.ImpressionType      = WINBIO_ANSI_381_IMP_TYPE_LIVE_SCAN_PLAIN;
    rec.Reserved            = 0;

    std::memcpy(out.data(), &hdr, sizeof(hdr));
    std::memcpy(out.data() + sizeof(hdr), &rec, sizeof(rec));
    std::memset(out.data() + sizeof(hdr) + sizeof(rec), kPlaceholderImageGray, kPlaceholderImageBytes);
    return out;
}

// Size of the BIR BuildVendorBir() produces for a payload of `payloadSize`.
inline size_t VendorBirSize(size_t payloadSize)
{
    const size_t standardOffset = Align8(sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER));
    const size_t vendorOffset   = Align8(standardOffset + PlaceholderAnsi381Size());
    return Align8(vendorOffset + payloadSize);
}

inline std::vector<uint8_t> BuildVendorBir(WINBIO_BIR_PURPOSE purpose,
                                           WINBIO_BIR_DATA_FLAGS flags,
                                           const std::vector<uint8_t>& payload)
{
    const size_t headerOffset   = sizeof(WINBIO_BIR);
    const size_t standardOffset = Align8(headerOffset + sizeof(WINBIO_BIR_HEADER));
    const std::vector<uint8_t> standard = BuildPlaceholderAnsi381();
    const size_t vendorOffset   = Align8(standardOffset + standard.size());
    std::vector<uint8_t> out(VendorBirSize(payload.size()), 0);

    WINBIO_BIR bir{};
    bir.HeaderBlock.Size   = static_cast<ULONG>(sizeof(WINBIO_BIR_HEADER));
    bir.HeaderBlock.Offset = static_cast<ULONG>(headerOffset);
    bir.StandardDataBlock.Size   = static_cast<ULONG>(standard.size());
    bir.StandardDataBlock.Offset = static_cast<ULONG>(standardOffset);
    bir.VendorDataBlock.Size   = static_cast<ULONG>(payload.size());
    bir.VendorDataBlock.Offset = static_cast<ULONG>(vendorOffset);
    // SignatureBlock stays {0,0}.

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
    // Format of the Standard Data Block (the placeholder above).
    header.BiometricDataFormat.Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    header.BiometricDataFormat.Type  = WINBIO_ANSI_381_FORMAT_TYPE;

    std::memcpy(out.data(), &bir, sizeof(bir));
    std::memcpy(out.data() + headerOffset, &header, sizeof(header));
    std::memcpy(out.data() + standardOffset, standard.data(), standard.size());
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
    // This project produces either no standard block or exactly the constant
    // placeholder (BuildPlaceholderAnsi381), and never a signature. The block's
    // content is deliberately not interpreted: it carries no trust.
    if ((bir.StandardDataBlock.Size != 0 &&
         bir.StandardDataBlock.Size != PlaceholderAnsi381Size()) ||
        bir.SignatureBlock.Size != 0) {
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