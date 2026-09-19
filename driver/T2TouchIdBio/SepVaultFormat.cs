// SPDX-License-Identifier: GPL-2.0-only
// SepVaultFormat.cs
//
// Writer side of the container read by service/T2SepBootstrap/SepVaultFormat.h.
// Layout must match that header exactly — see its comment for the field
// table. BinaryWriter on .NET writes little-endian for these primitive
// types on all currently-supported platforms, matching the C++ side's
// native (x64) byte order; there is no cross-platform concern here since
// both ends only ever run on the same Windows x64 machine.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace T2TouchId.SepVaultGui
{
    internal static class SepVaultFormat
    {
        private static readonly byte[] Magic =
            { (byte)'T', (byte)'2', (byte)'S', (byte)'E', (byte)'P', (byte)'V', (byte)'1', 0 };
        private const uint Version = 1;

        // DPAPI machine scope — deliberate, final choice (design doc §9.3):
        // no TPM on this hardware, this is the accepted floor, not a
        // placeholder. Machine scope (not user scope) because the reader is
        // a LocalSystem service that starts before any user profile is
        // loaded — user-scope DPAPI would have nothing to unprotect with at
        // that point.
        public static void Write(string path, byte[] keybagBytes, string password, int specialUserBag)
        {
            byte[] protectedKeybag = ProtectedData.Protect(keybagBytes, null, DataProtectionScope.LocalMachine);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] protectedPassword;
            try
            {
                protectedPassword = ProtectedData.Protect(passwordBytes, null, DataProtectionScope.LocalMachine);
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
            using var writer = new BinaryWriter(stream);

            writer.Write(Magic);
            writer.Write(Version);
            writer.Write(specialUserBag);
            writer.Write((uint)protectedKeybag.Length);
            writer.Write((uint)protectedPassword.Length);
            writer.Write(protectedKeybag);
            writer.Write(protectedPassword);

            // Restrict to SYSTEM + Administrators, mirroring the ACL pattern
            // the WBDI biometric device node itself needs (design doc §9.1,
            // §7.2) — DPAPI-machine protects the bytes, but the file itself
            // should not be world-readable while it's sitting on disk.
            var fileInfo = new FileInfo(path);
            var acl = fileInfo.GetAccessControl();
            acl.SetAccessRuleProtection(true, false); // strip inherited rules
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                "SYSTEM", System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                "Administrators", System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            fileInfo.SetAccessControl(acl);
        }
    }
}