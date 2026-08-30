// mailbox.c
//
// Direct semantic port (not literal code copy) of t2_sep_transport.c's
// t2_sep_wait_outbox / t2_sep_send / t2_sep_receive / t2_sep_control.
// Every offset, bit, and timeout is VERIFIED FROM SOURCE — see driver.h.

#include "driver.h"

static VOID T2StallMicroseconds(_In_ ULONG MinUs, _In_ ULONG MaxUs)
{
    // KeStallExecutionProcessor busy-waits; acceptable here because the
    // Linux reference also busy-polls (usleep_range 100-200us) and this
    // path runs at PASSIVE_LEVEL under a WDFWAITLOCK, never in a DPC.
    // A real implementation should prefer a short KeDelayExecutionThread
    // sleep once actual hardware timing is measured (VERIFIED ON WINDOWS
    // pending) - flagged for the milestone-2-hardware-results.md follow-up.
    ULONG mid = (MinUs + MaxUs) / 2;
    KeStallExecutionProcessor(mid);
}

NTSTATUS
T2MailboxWaitOutbox(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ ULONG TimeoutUs)
{
    ULONG waited = 0;

    while (waited < TimeoutUs) {
        ULONG status = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_STATUS));
        if (!(status & T2_SEP_OUTBOX_FULL_BIT)) {
            return STATUS_SUCCESS;
        }
        T2StallMicroseconds(T2_SEP_POLL_MIN_US, T2_SEP_POLL_MAX_US);
        waited += T2_SEP_POLL_MIN_US;
    }
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "T2TouchIdTransport: timed out waiting for SEP outbox to drain (%u us)\n", TimeoutUs));
    return STATUS_IO_TIMEOUT;
}

NTSTATUS
T2MailboxSend(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ const T2_SEP_MESSAGE *Message)
{
    NTSTATUS status = T2MailboxWaitOutbox(Ctx, T2_SEP_TIMEOUT_US);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // AppleSEPIntelIOP posts the final word last; it is always zero
    // (VERIFIED FROM SOURCE, t2_sep_transport.c comment reproduced exactly
    // because it documents required hardware ordering, not prose).
    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0x0), Message->Word[0]);
    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0x4), Message->Word[1]);
    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0x8), Message->Word[2]);
    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0xc), 0);

    return STATUS_SUCCESS;
}

NTSTATUS
T2MailboxReceive(_In_ PT2_DEVICE_CONTEXT Ctx, _Out_ T2_SEP_MESSAGE *Message, _In_ ULONG TimeoutUs)
{
    ULONG waited = 0;

    while (waited < TimeoutUs) {
        ULONG status = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));
        if (!(status & T2_SEP_INBOX_EMPTY_BIT)) {
            Message->Word[0] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0x0));
            Message->Word[1] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0x4));
            Message->Word[2] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0x8));
            // Reading the final word advances the hardware FIFO (VERIFIED
            // FROM SOURCE) - must stay last.
            Message->Word[3] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0xc));
            return STATUS_SUCCESS;
        }
        T2StallMicroseconds(T2_SEP_POLL_MIN_US, T2_SEP_POLL_MAX_US);
        waited += T2_SEP_POLL_MIN_US;
    }
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "T2TouchIdTransport: timed out waiting for SEP inbox reply (%u us)\n", TimeoutUs));
    return STATUS_IO_TIMEOUT;
}

NTSTATUS
T2SepControl(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Opcode, _In_ UINT8 Tag,
             _In_ PHYSICAL_ADDRESS Dma, _In_ SIZE_T Size)
{
    T2_SEP_MESSAGE request = { 0 };
    T2_SEP_MESSAGE reply;
    ULONG skipped = 0;
    NTSTATUS status;

    if ((Dma.QuadPart & (T2_SEP_DMA_ALIGNMENT - 1)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Dma.QuadPart >> T2_SEP_DMA_BITS) != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Size > MAXUINT32) {
        return STATUS_INVALID_PARAMETER;
    }

    // EP0 wire layout (VERIFIED FROM SOURCE): endpoint | tag<<8 | opcode<<16
    // | target_endpoint<<24 ; word[1] = dma_addr >> PAGE_SHIFT (12) ;
    // word[2] = size.
    request.Word[0] = T2_SEP_CONTROL_ENDPOINT
        | ((ULONG)Tag << 8)
        | ((ULONG)Opcode << 16)
        | ((ULONG)T2_SEP_AKS_ENDPOINT << 24);
    request.Word[1] = (ULONG)(Dma.QuadPart >> 12);
    request.Word[2] = (ULONG)Size;

    status = T2MailboxSend(Ctx, &request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        status = T2MailboxReceive(Ctx, &reply, T2_SEP_TIMEOUT_US);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        // Endpoint occupies the full low byte (tag<<8 begins immediately
        // after it in the wire layout above) — mask 0xff, matching the
        // equivalent parse in T2SepAksTransaction below. Do not narrow this
        // to 0x1f: that would fold any garbage/unrelated queued message
        // whose low byte happens to be e.g. 0x20 or 0xE0 into "endpoint 0"
        // and misroute it as our own reply.
        UINT8 endpoint = (UINT8)(reply.Word[0] & 0xff);
        UINT8 replyTag = (UINT8)((reply.Word[0] >> 8) & 0xff);
        if (endpoint == T2_SEP_CONTROL_ENDPOINT && replyTag == Tag) {
            break;
        }

        // Never surface asynchronous SEP payloads through this path - only
        // a debug trace, matching the Linux dev_dbg() equivalent.
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "T2TouchIdTransport: queued unrelated mailbox message from endpoint %u\n", endpoint));
        if (++skipped == T2_SEP_MAX_SKIPPED_REPLIES) {
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "T2TouchIdTransport: gave up waiting for control reply (opcode=%u tag=%u) "
                "after %u unrelated messages\n", Opcode, Tag, skipped));
            return STATUS_DEVICE_PROTOCOL_ERROR;
        }
    }

    if (reply.Word[1] != 0) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: control opcode %u returned SEP result 0x%x\n",
            Opcode, reply.Word[1]));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
T2SepAksTransaction(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Operation,
                     _In_ UINT8 Transaction, _In_ SIZE_T RequestWireLength,
                     _Out_ UINT16 *ReplyWireLength)
{
    T2_SEP_MESSAGE request = { 0 };
    T2_SEP_MESSAGE reply;
    ULONG skipped = 0;
    NTSTATUS status;

    *ReplyWireLength = 0;

    if (RequestWireLength > MAXUINT16) {
        // VERIFIED FROM SOURCE: reply/request length lives in the upper 16
        // bits of Word[1], so it can never exceed a 16-bit value in this
        // protocol (T2_SEP_OOL_SIZE is 0x4000, far below this ceiling —
        // this check is a defensive bound, not a real-world case).
        return STATUS_INVALID_PARAMETER;
    }

    // EP7 wire layout (VERIFIED FROM SOURCE, t2_aks_exchange_locked): NO
    // DMA address here — unlike EP0's T2SepControl, this endpoint addresses
    // the already-registered OOL_IN/OOL_OUT common buffers implicitly.
    // Word[0] = endpoint(7) | operation<<8 | transaction<<16.
    // Word[1] = requestWireLength<<16 (lower 16 bits unused/zero).
    request.Word[0] = T2_SEP_AKS_ENDPOINT
        | ((ULONG)Operation << 8)
        | ((ULONG)Transaction << 16);
    request.Word[1] = ((ULONG)RequestWireLength) << 16;

    status = T2MailboxSend(Ctx, &request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        status = T2MailboxReceive(Ctx, &reply, T2_SEP_TIMEOUT_US);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        // VERIFIED FROM SOURCE: reply match is (endpoint==7 &&
        // operation-bits-match && transaction-bits-match) — NOT the EP0
        // (endpoint,tag) pair. Operation occupies bits [14:8] (7 bits,
        // masked 0x7f) in the reply, transaction occupies bits [23:16].
        UINT8 replyEndpoint = (UINT8)(reply.Word[0] & 0xff);
        UINT8 replyOperation = (UINT8)((reply.Word[0] >> 8) & 0x7f);
        UINT8 replyTransaction = (UINT8)((reply.Word[0] >> 16) & 0xff);

        if (replyEndpoint == T2_SEP_AKS_ENDPOINT &&
            replyOperation == Operation &&
            replyTransaction == Transaction) {
            break;
        }

        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "T2TouchIdTransport: queued unrelated mailbox message from endpoint %u\n",
            replyEndpoint));
        if (++skipped == T2_SEP_MAX_SKIPPED_REPLIES) {
            return STATUS_DEVICE_PROTOCOL_ERROR;
        }
    }

    // VERIFIED FROM SOURCE: unlike EP0, Word[1] here is NOT a result code —
    // it is purely the reply wire length in its upper 16 bits. Success or
    // failure of the AKS operation itself is only knowable after parsing
    // and digest-validating the OOL_OUT buffer contents (caller's job).
    *ReplyWireLength = (UINT16)(reply.Word[1] >> 16);
    return STATUS_SUCCESS;
}