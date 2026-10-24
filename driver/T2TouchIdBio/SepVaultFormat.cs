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
using System.Security.AccessControl;
using System.Security.Principal;
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

            // Never expose a partially written or inheritably-readable final vault.
            // Stage the new file in the same directory, restrict its ACL while
            // empty, then atomically replace the final name on the same volume.
            string directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
            Directory.CreateDirectory(directory);
            string temporaryPath = Path.Combine(directory, ".t2sep-" + Path.GetRandomFileName());
            try
            {
                // Create empty first so that FileInfo can open it to set ACLs
                // without conflicting with a FileShare.None writer handle.
                using (new FileStream(temporaryPath, FileMode.CreateNew,
                                      FileAccess.Write, FileShare.None)) { }
                var fileInfo = new FileInfo(temporaryPath);
                var acl = new FileSecurity();
                acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl, AccessControlType.Allow));
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl, AccessControlType.Allow));
                fileInfo.SetAccessControl(acl);

                using (var stream = new FileStream(temporaryPath, FileMode.Open,
                                                   FileAccess.Write, FileShare.None))
                {
                    using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
                    writer.Write(Magic);
                    writer.Write(Version);
                    writer.Write(specialUserBag);
                    writer.Write((uint)protectedKeybag.Length);
                    writer.Write((uint)protectedPassword.Length);
                    writer.Write(protectedKeybag);
                    writer.Write(protectedPassword);
                    writer.Flush();
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temporaryPath, path, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
                Array.Clear(protectedKeybag, 0, protectedKeybag.Length);
                Array.Clear(protectedPassword, 0, protectedPassword.Length);
            }
        }
    }
}