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

    if ((version == T2_AKS_HEADER_V1 && headerSize != T2_AKS_HEADER_V1_SIZE) ||
        (version == T2_AKS_HEADER_V2 && headerSize != T2_AKS_HEADER_V2_SIZE) ||
        (version != T2_AKS_HEADER_V1 && version != T2_AKS_HEADER_V2) ||
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

static VOID
T2AksBuildHeaderV2(_Out_ PT2_AKS_HEADER_V2 Header)
{
    LARGE_INTEGER now;
    RtlZeroMemory(Header, sizeof(*Header));
    KeQuerySystemTimePrecise(&now);
    Header->V1.Version = T2_AKS_HEADER_V2;
    Header->V1.UsecTime = (UINT64)(now.QuadPart / 10); // 100ns -> us
    Header->CalendarSeconds = (UINT64)(now.QuadPart / 10000000);
}

NTSTATUS
T2AksExchange(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Operation,
              _In_reads_bytes_opt_(RequestLength) PUCHAR RequestBody, _In_ SIZE_T RequestLength,
              _Out_writes_bytes_to_(ResponseCapacity, *ResponseLength) PUCHAR ResponseBody,
              _In_ SIZE_T ResponseCapacity, _Out_ SIZE_T *ResponseLength)
{
    NTSTATUS status;
    T2_AKS_HEADER_V2 header;
    PUCHAR inBase = (PUCHAR)WdfCommonBufferGetAlignedVirtualAddress(Ctx->OolInBuffer);
    PUCHAR outBase = (PUCHAR)WdfCommonBufferGetAlignedVirtualAddress(Ctx->OolOutBuffer);
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
    requestWireLength = T2_AKS_V2_WIRE_SIZE + RequestLength;

    T2AksBuildHeaderV2(&header);

    RtlZeroMemory(inBase, T2_SEP_OOL_SIZE);
    RtlZeroMemory(outBase, T2_SEP_OOL_SIZE);

    // [u32 header_size][T2_AKS_HEADER_V2][body], per t2_aks_exchange_locked.
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

    // VERIFIED FROM SOURCE bounds: reply_length must be at least a bare V2
    // wire header and never exceed the physical OOL buffer size.
    if (replyWireLength < T2_AKS_V2_WIRE_SIZE || replyWireLength > T2_SEP_OOL_SIZE) {
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    RtlCopyMemory(&replyHeaderSize, outBase, sizeof(UINT32));
    RtlCopyMemory(&replyVersion, outBase + sizeof(UINT32) + 16, sizeof(UINT32));
    if (replyHeaderSize != T2_AKS_HEADER_V2_SIZE || replyVersion != T2_AKS_HEADER_V2) {
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
        }
        RtlSecureZeroMemory(expected, sizeof(expected));
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Only now — after header + digest validation — is it safe to trust
    // the reply's own claimed length to compute the body size. This
    // replaces the previous bug where body length was derived purely from
    // the CALLER's ResponseCapacity, independent of what the device
    // actually reported.
    {
        SIZE_T bodyLen = replyWireLength - T2_AKS_V2_WIRE_SIZE;
        if (bodyLen > ResponseCapacity) {
            // VERIFIED FROM SOURCE: the Linux ioctl handler returns -ENOSPC
            // in this situation rather than silently truncating.
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (bodyLen > 0 && ResponseBody != NULL) {
            RtlCopyMemory(ResponseBody, outBase + T2_AKS_V2_WIRE_SIZE, bodyLen);
        }
        *ResponseLength = bodyLen;
    }

    // Do NOT zero outBase here: SEP still considers it a live OOL buffer
    // per the pinning contract (Milestone 1) and may reuse it on the next
    // exchange without a fresh SET_OOL_OUT.
    return STATUS_SUCCESS;
}
