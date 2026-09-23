// SPDX-License-Identifier: GPL-2.0-only
// SepStatusClient.cs
//
// C# port of the read side of protocol/AppleKeyStore/Client's new
// SetBootstrapStatus/GetBootstrapStatus pair (see Client.h/Client.cpp and
// driver/T2TouchIdTransport/public.h). This does NOT touch AppleKeyStore
// or the SEP - it only opens the same device interface T2SepBootstrapService
// already talks to and reads the small in-memory status mailbox the driver
// holds (T2_BOOTSTRAP_STATUS), the same way t2touchid.exe or a native
// caller would via IOCTL_T2_GET_BOOTSTRAP_STATUS. The original "this GUI
// never touches the device" design (see MainWindow.xaml.cs's file header)
// still holds for anything AKS/SEP-related - this is a separate, narrower
// channel that exists purely for status reporting.
//
// No status file on disk anymore: the driver is the single source of
// truth for "what happened last", exactly as long as the PCI device stays
// loaded (i.e. for the whole boot session), which is exactly the lifetime
// this needs to matter for.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace T2TouchId.SepVaultGui
{
    public enum SepBootstrapReason : int
    {
        Unknown = 0,
        Ok = 1,
        VaultMissing = 2,
        Dpapi = 3,
        RegisterOolFailed = 4,
        SepHang = 5,
        SepRejected = 6,
    }

    public enum SepBootstrapStep : int
    {
        None = 0,
        ReadVault = 1,
        UnprotectKeybag = 2,
        UnprotectPassword = 3,
        RegisterOol = 4,
        LoadKeybag = 5,
        SetSystemKeybag = 6,
        UnlockHandle = 7,
        UnlockSpecialBag = 8,
        Ready = 9,
    }

    // Byte-for-byte mirror of driver/T2TouchIdTransport/public.h's
    // T2_BOOTSTRAP_STATUS on x64 (this project's only target platform per
    // README "Scope"). Pack = 1 with the padding written out explicitly
    // (see public.h's own comment on why Reserved is 7, not 3 bytes) so
    // this layout is exact rather than relying on the CLR to reproduce
    // MSVC's default alignment rules.
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SepBootstrapStatus
    {
        public int Reason;      // SepBootstrapReason
        public int Step;        // SepBootstrapStep
        public sbyte SepStatus;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public byte[] Reserved;
        public long TimestampUtc; // FILETIME-style 100ns ticks, 0 if never set

        public readonly SepBootstrapReason ReasonValue => (SepBootstrapReason)Reason;
        public readonly SepBootstrapStep StepValue => (SepBootstrapStep)Step;

        public readonly DateTime? TimestampLocal =>
            TimestampUtc == 0 ? null : DateTime.FromFileTimeUtc(TimestampUtc).ToLocalTime();
    }

    // Thrown when the device interface itself can't be found/opened - the
    // driver isn't loaded, or nothing has enumerated the PCI SEP function
    // yet. Distinct from "opened fine but Reason is Unknown" (service just
    // hasn't run yet this boot), which is a normal SepBootstrapStatus value,
    // not an exception.
    public sealed class SepDeviceNotFoundException : Exception
    {
        public SepDeviceNotFoundException() : base("T2TouchIdTransport device interface not found.") { }
    }

    public static class SepStatusClient
    {
        // {6E0F1A7C-6B7A-4E7A-9C6D-2C6B1E7F3A10} - GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT, public.h
        private static readonly Guid DeviceInterfaceGuid =
            new Guid("6E0F1A7C-6B7A-4E7A-9C6D-2C6B1E7F3A10");

        // IOCTL_T2_GET_BOOTSTRAP_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN=0x22,
        // 0x904, METHOD_BUFFERED, FILE_READ_ACCESS) - computed the same way
        // public.h's CTL_CODE macro does; kept as one literal here rather
        // than reimplementing CTL_CODE for a single call site.
        private const uint IOCTL_T2_GET_BOOTSTRAP_STATUS = 0x00226410;

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint OPEN_EXISTING = 3;
        private const uint DIGCF_PRESENT = 0x2;
        private const uint DIGCF_DEVICEINTERFACE = 0x10;

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVICE_INTERFACE_DATA
        {
            public int cbSize;
            public Guid InterfaceClassGuid;
            public int Flags;
            public IntPtr Reserved;
        }

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevsW(
            ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, uint Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInterfaces(
            IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid,
            uint MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool SetupDiGetDeviceInterfaceDetailW(
            IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
            IntPtr DeviceInterfaceDetailData, uint DeviceInterfaceDetailDataSize,
            out uint RequiredSize, IntPtr DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
            uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static string? FindDevicePath()
        {
            Guid guid = DeviceInterfaceGuid;
            IntPtr devInfo = SetupDiGetClassDevsW(ref guid, IntPtr.Zero, IntPtr.Zero,
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
            if (devInfo == IntPtr.Zero || devInfo == new IntPtr(-1)) return null;

            try
            {
                var ifData = new SP_DEVICE_INTERFACE_DATA
                {
                    cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>()
                };
                if (!SetupDiEnumDeviceInterfaces(devInfo, IntPtr.Zero, ref guid, 0, ref ifData))
                    return null;

                SetupDiGetDeviceInterfaceDetailW(devInfo, ref ifData, IntPtr.Zero, 0,
                    out uint requiredSize, IntPtr.Zero);
                if (requiredSize == 0) return null;

                IntPtr detailBuffer = Marshal.AllocHGlobal((int)requiredSize);
                try
                {
                    // SP_DEVICE_INTERFACE_DETAIL_DATA_W starts with a DWORD
                    // cbSize followed immediately by the WCHAR path - cbSize
                    // for a *variable-length* struct like this one must be
                    // sizeof(DWORD) + sizeof(WCHAR) on x64/x86 per the
                    // documented (if surprising) SetupAPI contract, not
                    // sizeof(the whole struct).
                    Marshal.WriteInt32(detailBuffer, IntPtr.Size == 8 ? 8 : 6);

                    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, ref ifData, detailBuffer,
                            requiredSize, out _, IntPtr.Zero))
                        return null;

                    return Marshal.PtrToStringUni(detailBuffer + 4);
                }
                finally
                {
                    Marshal.FreeHGlobal(detailBuffer);
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(devInfo);
            }
        }

        // Throws SepDeviceNotFoundException if the driver isn't loaded /
        // the device isn't present; throws Win32Exception for any other
        // failure (e.g. the IOCTL itself, which should not normally fail -
        // this is a plain in-memory read).
        public static SepBootstrapStatus GetStatus()
        {
            string? path = FindDevicePath();
            if (path == null) throw new SepDeviceNotFoundException();

            IntPtr handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new SepDeviceNotFoundException();

            try
            {
                int size = Marshal.SizeOf<SepBootstrapStatus>();
                IntPtr outBuffer = Marshal.AllocHGlobal(size);
                try
                {
                    bool ok = DeviceIoControl(handle, IOCTL_T2_GET_BOOTSTRAP_STATUS,
                        IntPtr.Zero, 0, outBuffer, (uint)size, out uint returned, IntPtr.Zero);
                    if (!ok || returned < size)
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    return Marshal.PtrToStructure<SepBootstrapStatus>(outBuffer);
                }
                finally
                {
                    Marshal.FreeHGlobal(outBuffer);
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }
    }
}