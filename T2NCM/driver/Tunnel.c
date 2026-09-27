// SPDX-License-Identifier: GPL-2.0-only
#include "Tunnel.h"

#define T2NCM_ETH_TYPE_IPV4  0x0800u
#define T2NCM_ETH_TYPE_IPV6  0x86DDu
#define T2NCM_IPPROTO_TCP    6u
#define T2NCM_IPPROTO_UDP    17u

static USHORT T2NcmReadBe16(_In_reads_bytes_(2) const UCHAR* p)
{
    return (USHORT)((p[0] << 8) | p[1]);
}

static VOID T2NcmWriteBe16(_Out_writes_bytes_(2) UCHAR* p, USHORT v)
{
    p[0] = (UCHAR)(v >> 8);
    p[1] = (UCHAR)(v & 0xFF);
}

static ULONG T2NcmChecksumFold(ULONG sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return sum;
}

static USHORT T2NcmIpChecksum(_In_reads_bytes_(HeaderLen) const UCHAR* Header, ULONG HeaderLen)
{
    ULONG sum = 0;
    ULONG i;
    for (i = 0; i + 1 < HeaderLen; i += 2)
        sum += ((ULONG)Header[i] << 8) | Header[i + 1];
    if (i < HeaderLen)
        sum += (ULONG)Header[i] << 8;
    return (USHORT)~T2NcmChecksumFold(sum);
}

// One's complement sum of 16-bit words; len may be odd.
static ULONG T2NcmSumBuffer(_In_reads_bytes_(Len) const UCHAR* Buf, ULONG Len)
{
    ULONG sum = 0;
    ULONG i;
    for (i = 0; i + 1 < Len; i += 2)
        sum += ((ULONG)Buf[i] << 8) | Buf[i + 1];
    if (i < Len)
        sum += (ULONG)Buf[i] << 8;
    return sum;
}

static USHORT T2NcmTcpChecksumV4(
    _In_reads_bytes_(20) const UCHAR* IpHdr,
    _In_reads_bytes_(TcpLen) const UCHAR* Tcp,
    ULONG TcpLen)
{
    ULONG sum = 0;
    sum += ((ULONG)IpHdr[12] << 8) | IpHdr[13];
    sum += ((ULONG)IpHdr[14] << 8) | IpHdr[15];
    sum += ((ULONG)IpHdr[16] << 8) | IpHdr[17];
    sum += ((ULONG)IpHdr[18] << 8) | IpHdr[19];
    sum += T2NCM_IPPROTO_TCP;
    sum += TcpLen & 0xFFFF;
    sum += T2NcmSumBuffer(Tcp, TcpLen);
    return (USHORT)~T2NcmChecksumFold(sum);
}

static USHORT T2NcmTcpChecksumV6(
    _In_reads_bytes_(16) const UCHAR* Src,
    _In_reads_bytes_(16) const UCHAR* Dst,
    _In_reads_bytes_(TcpLen) const UCHAR* Tcp,
    ULONG TcpLen)
{
    ULONG sum = 0;
    ULONG i;
    for (i = 0; i < 16; i += 2)
        sum += ((ULONG)Src[i] << 8) | Src[i + 1];
    for (i = 0; i < 16; i += 2)
        sum += ((ULONG)Dst[i] << 8) | Dst[i + 1];
    sum += (TcpLen >> 16) & 0xFFFF;
    sum += TcpLen & 0xFFFF;
    sum += T2NCM_IPPROTO_TCP;
    sum += T2NcmSumBuffer(Tcp, TcpLen);
    return (USHORT)~T2NcmChecksumFold(sum);
}

static VOID T2NcmMacToLinkLocal(_In_reads_bytes_(6) const UCHAR* Mac, _Out_writes_bytes_(16) UCHAR* Ip6)
{
    RtlZeroMemory(Ip6, 16);
    Ip6[0] = 0xFE;
    Ip6[1] = 0x80;
    Ip6[8] = Mac[0] ^ 0x02;
    Ip6[9] = Mac[1];
    Ip6[10] = Mac[2];
    Ip6[11] = 0xFF;
    Ip6[12] = 0xFE;
    Ip6[13] = Mac[3];
    Ip6[14] = Mac[4];
    Ip6[15] = Mac[5];
}

VOID T2NcmTunnelRefreshMode(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext)
{
    UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\T2TouchId\\Network");
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    NTSTATUS status;
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG resultLen = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"TransportMode");
    BOOLEAN enabled = FALSE;

    // PASSIVE_LEVEL only — never call from SendNetBufferLists / RX DPC.
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    InitializeObjectAttributes(&oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&key, KEY_READ, &oa);
    if (NT_SUCCESS(status))
    {
        status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation,
                                 buf, sizeof(buf), &resultLen);
        ZwClose(key);
        if (NT_SUCCESS(status) && info->Type == REG_DWORD &&
            info->DataLength >= sizeof(ULONG) &&
            (*(ULONG*)info->Data) == 1ul)
        {
            enabled = TRUE;
        }
    }

        DeviceContext->TunnelModeEnabled = enabled;

    {
        HANDLE key2 = NULL;
        OBJECT_ATTRIBUTES oa2;
        UNICODE_STRING path2 = path; /* same as TransportMode key */
        UNICODE_STRING peerName = RTL_CONSTANT_STRING(L"PeerIpv6");
        UCHAR pbuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 16];
        ULONG plen = 0;
        PKEY_VALUE_PARTIAL_INFORMATION pinfo = (PKEY_VALUE_PARTIAL_INFORMATION)pbuf;

        InitializeObjectAttributes(&oa2, &path2, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (NT_SUCCESS(ZwOpenKey(&key2, KEY_READ, &oa2))) {
            if (NT_SUCCESS(ZwQueryValueKey(key2, &peerName, KeyValuePartialInformation,
                                           pbuf, sizeof(pbuf), &plen)) &&
                pinfo->Type == REG_BINARY && pinfo->DataLength >= 16) {
                RtlCopyMemory(DeviceContext->TunnelPeerIpv6, pinfo->Data, 16);
                DeviceContext->TunnelPeerIpv6Valid = TRUE;
            }
            ZwClose(key2);
        }
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: TunnelModeEnabled=%u PeerIpv6Valid=%u (cached PASSIVE)\n",
        enabled ? 1u : 0u,
        DeviceContext->TunnelPeerIpv6Valid ? 1u : 0u));

}


VOID T2NcmTunnelNotePeerFromIpv6Frame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength)
{
    if (FrameLength < 14 + 40)
        return;
    if (T2NcmReadBe16(Frame + 12) != T2NCM_ETH_TYPE_IPV6)
        return;
    if ((Frame[14] >> 4) != 6)
        return;
    RtlCopyMemory(DeviceContext->TunnelPeerIpv6, Frame + 14 + 8, 16);
    DeviceContext->TunnelPeerIpv6Valid = TRUE;
}

BOOLEAN T2NcmTunnelRewriteTxIpv4ToIpv6(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Inout_updates_bytes_(BufferCapacity) PUCHAR Frame,
    _Inout_ PULONG FrameLength,
    _In_ ULONG BufferCapacity)
{
    ULONG fl;
    USHORT ethType;
    UCHAR ihl;
    UCHAR proto;
    ULONG ipHdrLen;
    ULONG payloadLen;
    ULONG newFl;
    UCHAR src6[16];
    UCHAR dst6[16];
    UCHAR tcpCopy[60];
    ULONG tcpHdrLen;
    UCHAR* tcp;
    USHORT oldCheck;

    if (!DeviceContext->TunnelModeEnabled)
        return TRUE;
    if (!DeviceContext->TunnelPeerIpv6Valid)
        return TRUE; // peer unknown yet — leave frame (will fail until RX learns)

    fl = *FrameLength;
    if (fl < 14 + 20)
        return TRUE;
    ethType = T2NcmReadBe16(Frame + 12);
    if (ethType != T2NCM_ETH_TYPE_IPV4)
        return TRUE;
    if (Frame[14] != 0x45) // v4, IHL=5 only for v1
        return TRUE;
    if (Frame[14 + 16] != 169 || Frame[14 + 17] != 254)
        return TRUE; // not APIPA dest

    ihl = Frame[14] & 0x0F;
    ipHdrLen = (ULONG)ihl * 4;
    proto = Frame[14 + 9];
    if (proto != T2NCM_IPPROTO_TCP && proto != T2NCM_IPPROTO_UDP)
        return TRUE;
    if (fl < 14 + ipHdrLen + 8)
        return TRUE;

    payloadLen = fl - 14 - ipHdrLen;
    newFl = 14 + 40 + payloadLen;
    if (newFl > BufferCapacity)
        return FALSE;

    RtlCopyMemory(dst6, DeviceContext->TunnelPeerIpv6, 16);
    if (DeviceContext->MacAddressValid)
        T2NcmMacToLinkLocal(DeviceContext->PermanentMacAddress, src6);
    else
        RtlZeroMemory(src6, 16), src6[0] = 0xFE, src6[1] = 0x80;

    // Move L4 payload to make room for IPv6 header (40 vs 20).
    RtlMoveMemory(Frame + 14 + 40, Frame + 14 + ipHdrLen, payloadLen);

    T2NcmWriteBe16(Frame + 12, T2NCM_ETH_TYPE_IPV6);
    RtlZeroMemory(Frame + 14, 40);
    Frame[14] = 0x60; // version 6
    T2NcmWriteBe16(Frame + 14 + 4, (USHORT)payloadLen);
    Frame[14 + 6] = proto;
    Frame[14 + 7] = 64; // hop limit
    RtlCopyMemory(Frame + 14 + 8, src6, 16);
    RtlCopyMemory(Frame + 14 + 24, dst6, 16);

    if (proto == T2NCM_IPPROTO_TCP && payloadLen >= 20) {
        tcp = Frame + 14 + 40;
        tcpHdrLen = (ULONG)((tcp[12] >> 4) * 4);
        if (tcpHdrLen >= 20 && tcpHdrLen <= payloadLen && tcpHdrLen <= sizeof(tcpCopy)) {
            RtlCopyMemory(tcpCopy, tcp, tcpHdrLen);
            tcpCopy[16] = 0;
            tcpCopy[17] = 0;
            oldCheck = T2NcmTcpChecksumV6(src6, dst6, tcpCopy, payloadLen);
            // recompute with zeroed checksum field over full TCP segment
            tcp[16] = 0;
            tcp[17] = 0;
            oldCheck = T2NcmTcpChecksumV6(src6, dst6, tcp, payloadLen);
            T2NcmWriteBe16(tcp + 16, oldCheck);
        }
    }

    *FrameLength = newFl;
    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm[POWER]: tunnel TX IPv4->IPv6 len %lu->%lu\n", fl, newFl));
    return TRUE;
}

BOOLEAN T2NcmTunnelRewriteRxIpv6ToIpv4(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Inout_updates_bytes_(*FrameLength) PUCHAR Frame,
    _Inout_ PULONG FrameLength)
{
    ULONG fl;
    USHORT ethType;
    UCHAR nextHdr;
    USHORT payloadLen;
    ULONG newFl;
    UCHAR src4[4];
    UCHAR dst4[4];
    const UCHAR* src6;
    UCHAR* tcp;
    USHORT csum;

    if (!DeviceContext->TunnelModeEnabled)
        return TRUE;

    fl = *FrameLength;
    if (fl < 14 + 40)
        return TRUE;
    ethType = T2NcmReadBe16(Frame + 12);
    if (ethType != T2NCM_ETH_TYPE_IPV6)
        return TRUE;
    if ((Frame[14] >> 4) != 6)
        return TRUE;

    T2NcmTunnelNotePeerFromIpv6Frame(DeviceContext, Frame, fl);

    nextHdr = Frame[14 + 6];
    payloadLen = T2NcmReadBe16(Frame + 14 + 4);
    if (nextHdr != T2NCM_IPPROTO_TCP && nextHdr != T2NCM_IPPROTO_UDP)
        return TRUE;
    if (fl < 14ul + 40ul + (ULONG)payloadLen)
        payloadLen = (USHORT)(fl - 14ul - 40ul);

    src6 = Frame + 14 + 8;
    // Map peer (src) to 169.254.x.y — same algorithm as userspace MapPeerToIpv4.
    {
        unsigned a = src6[14];
        unsigned b = src6[15];
        if (a == 0) a = 1;
        if (a == 255) a = 254;
        if (b == 0) b = 1;
        if (b == 255) b = 254;
        a = (a + src6[13]) % 254;
        if (a == 0) a = 1;
        src4[0] = 169; src4[1] = 254;
        src4[2] = (UCHAR)a; src4[3] = (UCHAR)b;
    }
    // Host APIPA: fixed 169.254.84.1 (GUI documents assigning this on the adapter).
    dst4[0] = 169; dst4[1] = 254; dst4[2] = 84; dst4[3] = 1;

    newFl = 14 + 20 + payloadLen;
    // Collapse: move L4 down over the extra 20 bytes of IPv6.
    RtlMoveMemory(Frame + 14 + 20, Frame + 14 + 40, payloadLen);
    T2NcmWriteBe16(Frame + 12, T2NCM_ETH_TYPE_IPV4);
    RtlZeroMemory(Frame + 14, 20);
    Frame[14] = 0x45;
    T2NcmWriteBe16(Frame + 14 + 2, (USHORT)(20 + payloadLen));
    Frame[14 + 8] = 64; // TTL
    Frame[14 + 9] = nextHdr;
    RtlCopyMemory(Frame + 14 + 12, src4, 4);
    RtlCopyMemory(Frame + 14 + 16, dst4, 4);
    {
        USHORT ipC = T2NcmIpChecksum(Frame + 14, 20);
        T2NcmWriteBe16(Frame + 14 + 10, ipC);
    }

    if (nextHdr == T2NCM_IPPROTO_TCP && payloadLen >= 20) {
        tcp = Frame + 14 + 20;
        tcp[16] = 0;
        tcp[17] = 0;
        csum = T2NcmTcpChecksumV4(Frame + 14, tcp, payloadLen);
        T2NcmWriteBe16(tcp + 16, csum);
    }

    *FrameLength = newFl;
    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm[POWER]: tunnel RX IPv6->IPv4 len %lu->%lu\n", fl, newFl));
    return TRUE;
}
