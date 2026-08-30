// akstore.c
//
// Endpoint-7 (AppleKeyStore) exchange. Wire format VERIFIED FROM SOURCE
// (t2_sep_transport.c, t2_aks_exchange_locked / t2_aks_digest):
//
//   wire = [u32 header_size][digest:16][version:4][usec_time:8][flags:4]
//          [clock_id:8][platform_data:32]{[calendar_seconds:8] if V2}[body]
//
// The 4-byte header_size length prefix comes BEFORE the digest and is NOT
// part of T2_AKS_HEADER_V1/V2 (driver.h) — it is hashed as part of "the
// rest of the header" only insofar as the header size value itself is
// trusted from the reply and range-checked, never included in the digest
// input (the digest input is exactly [digest-field-end .. end-of-message)).
//
// t2_aks_exchange_locked (the only path reachable from the Linux driver's
// ioctl, i.e. every allow-listed operation) always builds a V2 header. The
// V1 header only appears in the Linux driver's separate boot-time-only
// capability probe (a distinct code path this driver does not implement
// separately) — so this file always uses V2 for every exchange.
//
// The allow-list below is the actual security boundary of this whole
// component (Milestone 2, section 25). It is re-checked here even though
// device.c already checked it, so this function is safe to call from any
// future caller without relying on the IOCTL layer alone.

#include "driver.h"
#include <intrin.h>
#include <bcrypt.h>

BOOLEAN
T2AksOperationAllowed(_In_ UINT8 Operation)
{
    switch (Operation) {
    case T2AksOpLoadKeybag:
    case T2AksOpChangeLockState:
    case T2AksOpMakeSystemKeybag:
    case T2AksOpGetDeviceState:
    case T2AksOpGetCapabilities:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS
T2Sha256(_In_reads_bytes_(Length) PUCHAR Data, _In_ SIZE_T Length,
         _Out_writes_bytes_(16) PUCHAR DigestOut16)
{
    // AKS truncates SHA-256 to the first 16 bytes of the header digest
    // field (VERIFIED FROM SOURCE: digest field is 16 bytes, not 32).
    NTSTATUS status;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    UCHAR fullDigest[32];

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hash, Data, (ULONG)Length, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptFinishHash(hash, fullDigest, sizeof(fullDigest), 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    RtlCopyMemory(DigestOut16, fullDigest, 16);
    RtlSecureZeroMemory(fullDigest, sizeof(fullDigest));

cleanup:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return status;
}

// Message layout: [u32 header_size][T2_AKS_HEADER_V1{16-byte digest ...}]
// [...V2 tail if header_size == T2_AKS_HEADER_V2_SIZE][body]. Caller must
// have zeroed the 16-byte digest field before calling. VERIFIED FROM
// SOURCE: the header_size field itself is validated against the declared
// version before hashing/trusting Length — this mirrors t2_aks_digest's
// own defensive checks so a malformed reply can never smuggle a longer
// "trusted" length than the buffer actually holds.
NTSTATUS
T2AksDigest(_Inout_updates_bytes_(Length) PUCHAR Message, _In_ SIZE_T Length)
{
    UINT32 headerSize;
    UINT32 version;
    PUCHAR header;

    if (Length < sizeof(UINT32) + 16 + sizeof(UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&headerSize, Message, sizeof(UINT32));
    header = Message + sizeof(UINT32);
    RtlCopyMemory(&version, header + 16, sizeof(UINT32));

    if ((version == T2_AKS_VERSION_V1 && headerSize != T2_AKS_HEADER_V1_SIZE) ||
        (version == T2_AKS_VERSION_V2 && headerSize != T2_AKS_HEADER_V2_SIZE) ||
        (version != T2_AKS_VERSION_V1 && version != T2_AKS_VERSION_V2) ||
        (Length < sizeof(UINT32) + headerSize)) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Hash = (rest of header after the 16-byte digest field) ++ (body).
    // Equivalent to hashing Message[sizeof(u32)+16 .. Length) as one
    // contiguous run (VERIFIED FROM SOURCE: the two crypto_shash_update
    // calls in t2_aks_digest cover exactly this contiguous byte range,
    // split only because the Linux implementation reads header_size and
    // body from two different local variables).
    return T2Sha256(Message + sizeof(UINT32) + 16,
                     Length - sizeof(UINT32) - 16,
                     Message + sizeof(UINT32));
}

// Dump up to DumpLen bytes of the OOL_IN wire message for diagnosis.
// Only call for operations that carry no secret material (e.g. capabilities).
// Emits one T2_LOG line per 16 bytes so DebugView stays readable.
static VOID
T2AksDumpWire(_In_reads_bytes_(Length) PUCHAR Message, _In_ SIZE_T Length, _In_ SIZE_T DumpLen)
{
    SIZE_T n = (DumpLen < Length) ? DumpLen : Length;
    SIZE_T offset;

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: OolIn first %Iu of %Iu bytes:\n", n, Length));

    for (offset = 0; offset < n; offset += 16) {
        UCHAR b[16];
        SIZE_T i;
        SIZE_T chunk = (n - offset > 16) ? 16 : (n - offset);

        // Byte-by-byte fill keeps /analyze's readable-size model simple:
        // each Message[offset + i] is guarded by offset + i < Length
        // (n <= Length and i < chunk <= n - offset). Avoids C6385 on a
        // bulk RtlCopyMemory whose bound the analyzer does not always
        // prove from the ternary above.
        RtlZeroMemory(b, sizeof(b));
        for (i = 0; i < chunk; i++) {
            if (offset + i >= Length) {
                break;
            }
            b[i] = Message[offset + i];
        }

        // Fixed-width hex lines; unused trailing bytes of the last row are 00
        // only when chunk < 16 — still fine for diagnosis of the active prefix.
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport:  %04Ix: %02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X\n",
            offset,
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]));
    }
}


// Flush CPU write-back caches for [Va, Va+Length) so device DMA sees the
// data. Common-buffer memory is WB; without this SEP may read stale zeros.
// Uses clflush (x86/x64); KeMemoryBarrier alone is not sufficient.
static VOID
T2AksFlushForDevice(_In_reads_bytes_(Length) PVOID Va, _In_ SIZE_T Length)
{
    PUCHAR p = (PUCHAR)Va;
    PUCHAR end = p + Length;
    // Align down to cache line; clflush works on any address in the line.
    p = (PUCHAR)((ULONG_PTR)p & ~(ULONG_PTR)63);
    while (p < end) {
        _mm_clflush(p);
        p += 64;
    }
    _mm_mfence();
    KeMemoryBarrier();
}

static VOID
T2AksBuildHeaderV2(_Out_ PT2_AKS_HEADER_V2 Header)
{
    // Match Linux t2_aks_exchange_locked timestamps exactly:
    //   usec_time        = monotonic microseconds (ktime_get_ns / 1000)
    //   calendar_seconds = Unix epoch seconds (ktime_get_real_seconds)
    // Previous code used FILETIME (100 ns since 1601) for both fields,
    // which produces values ~3.7e10 larger than what SEP/bridgeOS expects
    // and can cause silent drops of the EP7 request.
    LARGE_INTEGER wall;
    ULONG64 interruptTime;
    RtlZeroMemory(Header, sizeof(*Header));
    KeQuerySystemTimePrecise(&wall);
    // Unbiased interrupt time is in 100 ns units and does not jump with
    // sleep/hibernate — closest kernel equivalent of ktime_get_ns().
    interruptTime = KeQueryUnbiasedInterruptTime();
    Header->V1.Version = T2_AKS_VERSION_V2;
    Header->V1.UsecTime = interruptTime / 10; // 100 ns → µs
    // FILETIME epoch (1601-01-01) → Unix epoch (1970-01-01) = 11644473600 s
    Header->CalendarSeconds = (UINT64)(wall.QuadPart / 10000000ULL) - 11644473600ULL;
}

NTSTATUS
T2AksExchange(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Operation,
              _In_reads_bytes_opt_(RequestLength) PUCHAR RequestBody, _In_ SIZE_T RequestLength,
              _Out_writes_bytes_to_opt_(ResponseCapacity, *ResponseLength) PUCHAR ResponseBody,
              _In_ SIZE_T ResponseCapacity, _Out_ SIZE_T *ResponseLength)
{
    NTSTATUS status;
    T2_AKS_HEADER_V2 header;
    PUCHAR inBase;
    PUCHAR outBase;
    SIZE_T requestWireLength;
    UINT16 replyWireLength;
    UINT8 transaction;
    UINT32 replyHeaderSize;
    UINT32 replyVersion;

    *ResponseLength = 0;

    if (!T2AksOperationAllowed(Operation)) {
        return STATUS_ACCESS_DENIED; // defense in depth; device.c already checked
    }

    if (RequestLength > T2_AKS_MAX_BODY_SIZE) {
        return STATUS_INVALID_BUFFER_SIZE; // VERIFIED FROM SOURCE: -EMSGSIZE bound
    }

    if (Ctx->OolInVa == NULL || Ctx->OolOutVa == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    inBase = (PUCHAR)Ctx->OolInVa;
    outBase = (PUCHAR)Ctx->OolOutVa;

    // DIAGNOSTIC: confirm these are still the exact buffers SEP was told
    // about in T2DmaRegisterOolBuffers (WDF logical address).
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: AKS exchange using OolIn phys=0x%llx OolOut phys=0x%llx "
        "(InRegistered=%d OutRegistered=%d WDF-logical)\n",
        Ctx->OolInPa.QuadPart, Ctx->OolOutPa.QuadPart,
        Ctx->OolInRegistered, Ctx->OolOutRegistered));

    RtlZeroMemory(inBase, T2_SEP_OOL_SIZE);
    RtlZeroMemory(outBase, T2_SEP_OOL_SIZE);

    // Always V2 — matches Linux t2_aks_exchange_locked / t2-aks-tool ioctl
    // path (proven for capabilities on real hardware). Combined with
    // non-cached + prefer-<4GB OOL buffers.
    requestWireLength = T2_AKS_V2_WIRE_SIZE + RequestLength;
    T2AksBuildHeaderV2(&header);

    *(UINT32*)inBase = T2_AKS_HEADER_V2_SIZE;
    RtlCopyMemory(inBase + sizeof(UINT32), &header, sizeof(header));
    if (RequestBody && RequestLength > 0) {
        RtlCopyMemory(inBase + T2_AKS_V2_WIRE_SIZE, RequestBody, RequestLength);
    }

    status = T2AksDigest(inBase, requestWireLength);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(inBase, requestWireLength);
        return status;
    }

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: AKS wire header_size=0x%x digest0..3=%02x%02x%02x%02x version=%u "
        "requestWireLength=%Iu bodyLength=%Iu\n",
        *(UINT32*)inBase, inBase[4], inBase[5], inBase[6], inBase[7],
        header.V1.Version, requestWireLength, RequestLength));
    // Full dump for capabilities (no secrets); header-only otherwise.
    if (Operation == T2AksOpGetCapabilities || Operation == T2AksOpGetDeviceState) {
        T2AksDumpWire(inBase, requestWireLength, 128);
    } else {
        T2AksDumpWire(inBase, requestWireLength, T2_AKS_V2_WIRE_SIZE);
    }

    // Snapshot before flush for readback check.
    {
        UCHAR snap[128];
        SIZE_T snapLen = (requestWireLength < sizeof(snap)) ? requestWireLength : sizeof(snap);
        RtlCopyMemory(snap, inBase, snapLen);

        // CPU -> device: flush WB cache lines so SEP DMA reads the wire we built.
        T2AksFlushForDevice(inBase, requestWireLength);

        // Readback: after clflush+mfence the CPU must still see the same bytes.
        // If this fails, the VA mapping is broken / not the buffer SEP will DMA.
        {
            SIZE_T i;
            BOOLEAN mismatch = FALSE;
            for (i = 0; i < snapLen; ++i) {
                if (inBase[i] != snap[i]) {
                    mismatch = TRUE;
                    break;
                }
            }
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "T2TouchIdTransport: OolIn readback after flush: %s (checked %Iu bytes)%s\n",
                mismatch ? "MISMATCH" : "OK",
                snapLen,
                mismatch ? " — VA may not match device-visible memory" : ""));
            if (mismatch) {
                T2AksDumpWire(inBase, requestWireLength, snapLen);
            }
        }

        // Field-by-field (Linux t2_aks_exchange_locked layout):
        //   [0:4]  header_size = 0x50
        //   [4:20] digest (16)
        //   [20:24] version = 2
        //   [24:32] usec_time
        //   [32:36] flags
        //   [36:44] clock_id
        //   [44:76] platform_data[32]
        //   [76:84] calendar_seconds   (abs 0x4C..0x53)
        //   [84:]   body               (abs 0x54+)
        {
            UINT32 hs=0, ver=0, flags=0;
            UINT64 usec=0, clock=0, cal=0;
            RtlCopyMemory(&hs, inBase + 0, 4);
            RtlCopyMemory(&ver, inBase + 20, 4);
            RtlCopyMemory(&usec, inBase + 24, 8);
            RtlCopyMemory(&flags, inBase + 32, 4);
            RtlCopyMemory(&clock, inBase + 36, 8);
            RtlCopyMemory(&cal, inBase + 0x4C, 8);
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "T2TouchIdTransport: V2 fields hs=0x%x ver=%u usec=%llu flags=0x%x "
                "clock=%llu cal=%llu body0..3=%02x%02x%02x%02x\n",
                hs, ver, usec, flags, clock, cal,
                (requestWireLength > 0x54) ? inBase[0x54] : 0,
                (requestWireLength > 0x55) ? inBase[0x55] : 0,
                (requestWireLength > 0x56) ? inBase[0x56] : 0,
                (requestWireLength > 0x57) ? inBase[0x57] : 0));
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "T2TouchIdTransport: EP7 doorbell will be word0=ep7|op<<8|txn<<16 "
                "word1=wireLen<<16 (Linux t2_aks_exchange_locked identical)\n"));
        }
    }

    // VERIFIED FROM SOURCE: transaction is a free-running byte counter that
    // skips 0 (0 is reserved / never a valid transaction id on this path).
    Ctx->NextTransaction++;
    if (Ctx->NextTransaction == 0) {
        Ctx->NextTransaction++;
    }
    transaction = Ctx->NextTransaction;

    status = T2SepAksTransaction(Ctx, Operation, transaction, requestWireLength, &replyWireLength);
    RtlSecureZeroMemory(inBase, requestWireLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Device -> CPU: invalidate cache so we observe SEP's write to OOL_OUT.
    T2AksFlushForDevice(outBase, T2_SEP_OOL_SIZE);

    // replyWireLength==0: SEP posted a mailbox ack with no OOL payload
    // (seen for get_device_state with handle=0 — endpoint alive, no body).
    if (replyWireLength == 0) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "T2TouchIdTransport: AKS reply has zero wire length "
            "(operation=0x%02x transaction=0x%02x) — mailbox ack only, no OOL body\n",
            Operation, transaction));
        *ResponseLength = 0;
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Accept either V1 or V2 reply header.
    if (replyWireLength < T2_AKS_V1_WIRE_SIZE || replyWireLength > T2_SEP_OOL_SIZE) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: AKS reply rejected - replyWireLength=%u out of bounds "
            "(expect >=%u, <=%u)\n", replyWireLength, (UINT32)T2_AKS_V1_WIRE_SIZE, T2_SEP_OOL_SIZE));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    // Dump OOL_OUT for diagnostic ops so we can verify digest/body.
    if (Operation == T2AksOpGetCapabilities || Operation == T2AksOpGetDeviceState) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport: OolOut reply wireLength=%u:\n", replyWireLength));
        T2AksDumpWire(outBase, replyWireLength, 128);
    }

    RtlCopyMemory(&replyHeaderSize, outBase, sizeof(UINT32));
    RtlCopyMemory(&replyVersion, outBase + sizeof(UINT32) + 16, sizeof(UINT32));
    if (!((replyHeaderSize == T2_AKS_HEADER_V2_SIZE && replyVersion == T2_AKS_VERSION_V2) ||
          (replyHeaderSize == T2_AKS_HEADER_V1_SIZE && replyVersion == T2_AKS_VERSION_V1))) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: AKS reply rejected - replyHeaderSize=0x%x replyVersion=%u "
            "(expected V1 0x%x or V2 0x%x)\n",
            replyHeaderSize, replyVersion, T2_AKS_HEADER_V1_SIZE, T2_AKS_HEADER_V2_SIZE));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    // Digest validation: recompute over a scratch copy of the digest field
    // so a malformed/forged reply can never be treated as valid even
    // transiently (VERIFIED FROM SOURCE: Linux zeroes the field in-place,
    // recomputes, and memcmp's against the saved original — same effect).
    {
        UCHAR expected[16];
        RtlCopyMemory(expected, outBase + sizeof(UINT32), sizeof(expected));
        RtlZeroMemory(outBase + sizeof(UINT32), sizeof(expected));

        status = T2AksDigest(outBase, replyWireLength);
        if (NT_SUCCESS(status) &&
            RtlCompareMemory(expected, outBase + sizeof(UINT32), sizeof(expected)) != sizeof(expected)) {
            status = STATUS_INVALID_DEVICE_STATE; // digest mismatch: never trust body
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "T2TouchIdTransport: AKS reply rejected - digest mismatch (operation=0x%02x "
                "transaction=0x%02x replyWireLength=%u)\n", Operation, transaction, replyWireLength));
        }
        RtlSecureZeroMemory(expected, sizeof(expected));
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Body starts after the wire header that matches the reply version.
    {
        SIZE_T wireHeaderSize = (replyVersion == T2_AKS_VERSION_V1)
            ? T2_AKS_V1_WIRE_SIZE : T2_AKS_V2_WIRE_SIZE;
        SIZE_T bodyLen = replyWireLength - wireHeaderSize;
        if (bodyLen > ResponseCapacity) {
            // VERIFIED FROM SOURCE: the Linux ioctl handler returns -ENOSPC
            // in this situation rather than silently truncating.
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (bodyLen > 0 && ResponseBody != NULL) {
            RtlCopyMemory(ResponseBody, outBase + wireHeaderSize, bodyLen);
        }
        *ResponseLength = bodyLen;
    }

    // Do NOT zero outBase here: SEP still considers it a live OOL buffer
    // per the pinning contract (Milestone 1) and may reuse it on the next
    // exchange without a fresh SET_OOL_OUT.
    return STATUS_SUCCESS;
}