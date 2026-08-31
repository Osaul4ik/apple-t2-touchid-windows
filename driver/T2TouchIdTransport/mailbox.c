// SPDX-License-Identifier: GPL-2.0-only
// mailbox.c
//
// Direct semantic port (not literal code copy) of t2_sep_transport.c's
// t2_sep_wait_outbox / t2_sep_send / t2_sep_receive / t2_sep_control.
// Every offset, bit, and timeout is VERIFIED FROM SOURCE — see driver.h.

#include "driver.h"

// Milestone 2B §9: monotonic microsecond clock for bounding total
// transaction time, independent of wall-clock/system-time changes.
// KeQueryInterruptTime returns 100ns units and needs no frequency lookup.
static ULONGLONG T2NowUs(VOID)
{
    return KeQueryInterruptTime() / 10;
}

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
    NTSTATUS status;
    ULONG preOutbox, preInbox, postOutbox, postInbox;
    UINT8 ep = (UINT8)(Message->Word[0] & 0xff);

    preOutbox = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_STATUS));
    preInbox  = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));

    status = T2MailboxWaitOutbox(Ctx, T2_SEP_TIMEOUT_US);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Linux t2_sep_send sequence (identical):
    //   wait !OUTBOX_FULL
    //   writel word0 @ OUTBOX_DATA+0x0
    //   writel word1 @ OUTBOX_DATA+0x4
    //   writel word2 @ OUTBOX_DATA+0x8
    //   writel 0     @ OUTBOX_DATA+0xc   // doorbell, always last
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: MMIO SEND ep=%u pre outbox=0x%x (full=%d seq=0x%x) "
        "inbox=0x%x (empty=%d) words=%08x %08x %08x 00000000\n",
        ep, preOutbox, (preOutbox & T2_SEP_OUTBOX_FULL_BIT) != 0, preOutbox & 0xffff,
        preInbox, (preInbox & T2_SEP_INBOX_EMPTY_BIT) != 0,
        Message->Word[0], Message->Word[1], Message->Word[2]));

    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0x0), Message->Word[0]);
    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0x4), Message->Word[1]);
    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0x8), Message->Word[2]);
    WRITE_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_DATA + 0xc), 0);

    // Read-back status forces posted MMIO writes to complete (x86).
    postOutbox = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_STATUS));
    postInbox  = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: MMIO SEND done ep=%u post outbox=0x%x (full=%d seq=0x%x) "
        "inbox=0x%x (empty=%d) seq_delta=%d\n",
        ep, postOutbox, (postOutbox & T2_SEP_OUTBOX_FULL_BIT) != 0, postOutbox & 0xffff,
        postInbox, (postInbox & T2_SEP_INBOX_EMPTY_BIT) != 0,
        (int)((postOutbox & 0xffff) - (preOutbox & 0xffff))));

    // Compatibility with existing log parsers
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: SEP send word0=0x%08x word1=0x%08x word2=0x%08x\n",
        Message->Word[0], Message->Word[1], Message->Word[2]));
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: SEP send complete, outbox status=0x%x full=%d\n",
        postOutbox, (postOutbox & T2_SEP_OUTBOX_FULL_BIT) != 0));

    return STATUS_SUCCESS;
}

NTSTATUS
T2MailboxReceive(_In_ PT2_DEVICE_CONTEXT Ctx, _Out_ T2_SEP_MESSAGE *Message, _In_ ULONG TimeoutUs)
{
    ULONG waited = 0;

    while (waited < TimeoutUs) {
        ULONG status = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));
        // Heartbeat every 1s so we can see whether inbox/outbox bits move at all
        // during an EP7 timeout (proves SEP is alive but silent vs frozen).
        if (waited > 0 && (waited % 1000000) < T2_SEP_POLL_MIN_US) {
            ULONG ob = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_STATUS));
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "T2TouchIdTransport: MMIO WAIT %u ms inbox=0x%x empty=%d outbox=0x%x full=%d seq=0x%x\n",
                waited / 1000, status, (status & T2_SEP_INBOX_EMPTY_BIT) != 0,
                ob, (ob & T2_SEP_OUTBOX_FULL_BIT) != 0, ob & 0xffff));
        }
        if (!(status & T2_SEP_INBOX_EMPTY_BIT)) {
            Message->Word[0] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0x0));
            Message->Word[1] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0x4));
            Message->Word[2] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0x8));
            // Reading the final word advances the hardware FIFO (VERIFIED
            // FROM SOURCE) - must stay last.
            Message->Word[3] = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_DATA + 0xc));
            // DIAGNOSTIC: log every message the FIFO ever hands us here,
            // not just the "unrelated" ones the callers trace - if the
            // caller's match check itself is ever wrong, this is the only
            // place that will show the raw bytes it wrongly rejected.
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "T2TouchIdTransport: SEP receive word0=0x%08x word1=0x%08x word2=0x%08x waited=%u us\n",
                Message->Word[0], Message->Word[1], Message->Word[2], waited));
            return STATUS_SUCCESS;
        }
        T2StallMicroseconds(T2_SEP_POLL_MIN_US, T2_SEP_POLL_MAX_US);
        waited += T2_SEP_POLL_MIN_US;
    }
    // DIAGNOSTIC: on a real timeout, capture a final inbox/outbox snapshot.
    // This distinguishes "SEP never touched the mailbox again" (outbox
    // still shows whatever it was right after our send, inbox still empty)
    // from "something is toggling the registers but never sets INBOX_EMPTY
    // to 0" (would show a changing/odd inbox value across repeated runs).
    {
        ULONG finalInbox = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));
        ULONG finalOutbox = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_STATUS));
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: timed out waiting for SEP inbox reply (%u us); "
            "final inbox=0x%x empty=%d outbox=0x%x full=%d\n",
            TimeoutUs, finalInbox, (finalInbox & T2_SEP_INBOX_EMPTY_BIT) != 0,
            finalOutbox, (finalOutbox & T2_SEP_OUTBOX_FULL_BIT) != 0));
    }
    return STATUS_IO_TIMEOUT;
}

NTSTATUS
T2SepControl(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Opcode, _In_ UINT8 Tag,
             _In_ PHYSICAL_ADDRESS Dma, _In_ SIZE_T Size, _Out_opt_ PBOOLEAN SentToDevice)
{
    T2_SEP_MESSAGE request = { 0 };
    T2_SEP_MESSAGE reply;
    ULONG skipped = 0;
    NTSTATUS status;

    if (SentToDevice) {
        *SentToDevice = FALSE;
    }

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

    // The doorbell has now been rung: this message has physically left for
    // SEP. Everything from here on (reply wait, skip counting, deadline) can
    // still fail without that meaning SEP never saw it - report "sent" now,
    // independent of whatever this function ends up returning.
    if (SentToDevice) {
        *SentToDevice = TRUE;
    }

    // Milestone 2B §9: overall wall-clock bound for this whole transaction,
    // independent of how many unrelated messages get skipped along the
    // way - see T2_SEP_TRANSACTION_DEADLINE_US in driver.h.
    ULONGLONG deadlineUs = T2NowUs() + T2_SEP_TRANSACTION_DEADLINE_US;

    for (;;) {
        ULONGLONG nowUs = T2NowUs();
        if (nowUs >= deadlineUs) {
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "T2TouchIdTransport: control transaction (opcode=%u tag=%u) exceeded "
                "overall deadline of %llu us after %u skipped messages\n",
                Opcode, Tag, T2_SEP_TRANSACTION_DEADLINE_US, skipped));
            return STATUS_IO_TIMEOUT;
        }
        ULONGLONG remainingUs = deadlineUs - nowUs;
        ULONG pollTimeoutUs = (remainingUs < (ULONGLONG)T2_SEP_TIMEOUT_US)
            ? (ULONG)remainingUs : (ULONG)T2_SEP_TIMEOUT_US;

        status = T2MailboxReceive(Ctx, &reply, pollTimeoutUs);
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

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: AKS exchange start operation=0x%02x transaction=0x%02x wireLength=%Iu\n",
        Operation, Transaction, RequestWireLength));

    status = T2MailboxSend(Ctx, &request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Milestone 2B §9: same overall deadline bound as T2SepControl above.
    ULONGLONG deadlineUs = T2NowUs() + T2_SEP_TRANSACTION_DEADLINE_US;

    for (;;) {
        ULONGLONG nowUs = T2NowUs();
        if (nowUs >= deadlineUs) {
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "T2TouchIdTransport: AKS transaction (operation=0x%02x transaction=0x%02x) "
                "exceeded overall deadline of %llu us after %u skipped messages\n",
                Operation, Transaction, T2_SEP_TRANSACTION_DEADLINE_US, skipped));
            return STATUS_IO_TIMEOUT;
        }
        ULONGLONG remainingUs = deadlineUs - nowUs;
        ULONG pollTimeoutUs = (remainingUs < (ULONGLONG)T2_SEP_TIMEOUT_US)
            ? (ULONG)remainingUs : (ULONG)T2_SEP_TIMEOUT_US;

        status = T2MailboxReceive(Ctx, &reply, pollTimeoutUs);
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
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: AKS exchange matched operation=0x%02x transaction=0x%02x replyWireLength=%u (skipped=%u)\n",
        Operation, Transaction, *ReplyWireLength, skipped));
    return STATUS_SUCCESS;
}