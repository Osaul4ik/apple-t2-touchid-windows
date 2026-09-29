// SPDX-License-Identifier: GPL-2.0-only
// MainWindow.xaml.cs — SEP status + one-time keybag setup UI, design doc §9.1.
//
// Diagnostic / logging controls live in the "Developer tools" card, which is
// hidden until the Developer mode switch (footer) is turned on.
//
// Vault import (OnBrowseKeybag/OnSave) still never talks to
// protocol/AppleKeyStore or the SEP - it only ever produces sep-vault.bin,
// same as before. T2SepBootstrap is what actually validates it against
// hardware on the next boot (T2SepBootstrapService.cpp), and its outcome
// is what LoadSepStatus() below reads back — via SepStatusClient's
// IOCTL_T2_GET_BOOTSTRAP_STATUS query, not by touching AppleKeyStore
// either. Free-text detail beyond the summary shown here still only lives
// in C:\LogSEP.txt.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Microsoft.Win32;

namespace T2TouchId.SepVaultGui
{
    public partial class MainWindow : Window
    {
        private const string VaultPath = @"C:\ProgramData\T2TouchId\sep-vault.bin";
        private byte[]? _keybagBytes;

        private static readonly Brush DotUnknown = new SolidColorBrush(Color.FromRgb(0x9C, 0xA3, 0xAF));
        private static readonly Brush DotOk = new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A));
        private static readonly Brush DotWarn = new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06));
        private static readonly Brush DotError = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26));
        private static readonly Brush TextMuted = new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80));

        public MainWindow()
        {
            InitializeComponent();
            LoadSepStatus();
            LoadLogFlags();
            LoadShortVerify();
            LoadLockOnDisplayOff();
            LoadVaultState();
            LoadTransportMode();
            LoadDevMode();
        }

        // ---- Developer mode (GUI-only switch) ----
        // Hides the diagnostic / logging controls until it is switched on.
        // Persisted so it survives restarts; a failed write (no admin rights)
        // only means the switch is not remembered - it still works this session.
        private const string GuiRegPath = @"SOFTWARE\T2TouchId\Gui";
        private const string DevModeValue = "DevMode";
        private bool _devModeLoading;

        private static bool ReadDevMode()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(GuiRegPath, false);
                return key?.GetValue(DevModeValue) is int i && i != 0;
            }
            catch { return false; }
        }

        private static void WriteDevMode(bool enabled)
        {
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(GuiRegPath, true);
                key?.SetValue(DevModeValue, enabled ? 1 : 0, RegistryValueKind.DWord);
            }
            catch { /* best effort */ }
        }

        private void LoadDevMode()
        {
            _devModeLoading = true;
            try
            {
                bool on = ReadDevMode();
                DevModeToggle.IsChecked = on;
                ApplyDevMode(on, animate: false);
            }
            finally
            {
                _devModeLoading = false;
            }
        }

        private void OnDevModeChanged(object sender, RoutedEventArgs e)
        {
            if (_devModeLoading) return;
            bool on = DevModeToggle.IsChecked == true;
            WriteDevMode(on);
            ApplyDevMode(on, animate: true);
        }

        private void ApplyDevMode(bool on, bool animate)
        {
            if (!on)
            {
                DevPanel.BeginAnimation(OpacityProperty, null);
                DevPanel.Visibility = Visibility.Collapsed;
                return;
            }

            DevPanel.Visibility = Visibility.Visible;
            if (!animate) return;

            DevPanel.BeginAnimation(OpacityProperty,
                new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(180))));
            Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() => DevPanel.BringIntoView()));
        }

        public void RefreshTransportUi()
        {
            LoadTransportMode();
        }


        // ---- Network transport mode (manual only) ----
        // Session flag: HKLM\SOFTWARE\T2TouchId\Network\Session\SkipNativeIpv6Probe
        // Live: IOCTL to \\.\T2Ncm + optional peer push + TCP warm poke.
        private const string SessionRegPath = @"SOFTWARE\T2TouchId\Network\Session";
        private const string NetworkRegPath = @"SOFTWARE\T2TouchId\Network";
        private const string SkipNativeIpv6ProbeValue = "SkipNativeIpv6Probe";
        private const string PeerIpv6Value = "PeerIpv6";
        // Persistent setting (HKLM\SOFTWARE\T2TouchId\Network\AutoSwitch, DWORD).
        // Missing == ON. Read by the native side (TransportMode.h IsAutoSwitchEnabled).
        private const string AutoSwitchValue = "AutoSwitch";
        // Bumped on every transport change so a running Bio service re-probes
        // Native IPv6 immediately instead of waiting for a network event.
        private const string ReprobeNonceValue = "ReprobeNonce";
        private bool _transportLoading;

        private static bool ReadAutoSwitch()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(NetworkRegPath, false);
                return !(key?.GetValue(AutoSwitchValue) is int i && i == 0);
            }
            catch { return true; }
        }

        private static bool WriteAutoSwitch(bool enabled)
        {
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(NetworkRegPath, true);
                if (key == null) return false;
                key.SetValue(AutoSwitchValue, enabled ? 1 : 0, RegistryValueKind.DWord);
                BumpReprobeNonce();
                return true;
            }
            catch { return false; }
        }

        // The Session key must be VOLATILE (gone after reboot) - a forced-tunnel
        // box that survives a reboot silently pins every future boot. Plain
        // CreateSubKey(path) would create it non-volatile.
        private static RegistryKey? CreateSessionKey() =>
            Registry.LocalMachine.CreateSubKey(SessionRegPath,
                RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.Volatile);

        private static void BumpReprobeNonce()
        {
            try
            {
                using var key = CreateSessionKey();
                if (key == null) return;
                int n = key.GetValue(ReprobeNonceValue) is int v ? v : 0;
                key.SetValue(ReprobeNonceValue, unchecked(n + 1), RegistryValueKind.DWord);
            }
            catch { /* best effort - network/session events still trigger a re-probe */ }
        }

        /// <summary>Set the persistent auto-switch flag from the command line.</summary>
        public static bool ApplyAutoSwitchFromCommandLine(bool enabled) => WriteAutoSwitch(enabled);

        private void LoadTransportMode()
        {
            _transportLoading = true;
            try
            {
                bool tunnel = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(SessionRegPath, false);
                    if (key?.GetValue(SkipNativeIpv6ProbeValue) is int i)
                        tunnel = i != 0;
                }
                catch { /* default native */ }
                bool auto = ReadAutoSwitch();
                Ipv4TunnelCheck.IsChecked = tunnel;
                AutoSwitchCheck.IsChecked = auto;
                TransportStatusText.Text = tunnel
                    ? "Mode: IPv4 tunnel forced (automatic fallback is inactive while forced)."
                    : auto
                        ? "Mode: automatic. Native IPv6, with an instant switch to the IPv4 tunnel if it is unavailable (VPN)."
                        : "Mode: Native IPv6 (automatic fallback is off).";
                TransportStatusText.Foreground = TextMuted;
                if (WarmupStatusText != null)
                {
                    WarmupStatusText.Text = auto
                        ? "Enabled (default)."
                        : "Disabled: using Native IPv6 (or the forced tunnel).";
                    WarmupDetailText.Text = "Returns to IPv6 on events: VPN connected/disconnected, unlock, resume from sleep. CLI: SepVaultGui.exe --auto | --no-auto";
                }
            }
            finally
            {
                _transportLoading = false;
            }
        }

        /// <summary>
        /// Apply transport from GUI checkbox or command line. Warms immediately
        /// (registry + live mode IOCTL + peer IOCTL + throwaway TCP SYN).
        /// </summary>
        public static bool ApplyTransportFromCommandLine(bool tunnel)
        {
            return ApplyTransportCore(tunnel, out string status);
        }

        private static bool ApplyTransportCore(bool tunnel, out string status)
        {
            try
            {
                using (var key = CreateSessionKey())
                {
                    if (key == null)
                    {
                        status = "Could not open the Session key";
                        return false;
                    }
                    if (tunnel)
                        key.SetValue(SkipNativeIpv6ProbeValue, 1, RegistryValueKind.DWord);
                    else
                        key.DeleteValue(SkipNativeIpv6ProbeValue, throwOnMissingValue: false);
                }

                BumpReprobeNonce();
                bool pushed = PushTransportModeToDriver(tunnel ? 1 : 0);
                bool peerOk = true;
                if (tunnel)
                {
                    peerOk = PushPersistedPeerToDriver();
                    // Windows' real fe80 must reach the driver explicitly: with a VPN
                    // already up no native IPv6 frame leaves for it to learn from.
                    PushLocalLinkLocalToDriver();
                    // Best-effort datapath warm so T2Ncm learns local addresses.
                    WarmTunnelDatapathFromPersistedPeer();
                }

                status = tunnel
                    ? (pushed
                        ? "IPv4 tunnel enabled (registry + live IOCTL" + (peerOk ? ", peer" : ", peer skip") + ", warm)."
                        : "IPv4 tunnel: registry OK, but \\\\.\\T2Ncm is unavailable.")
                    : (pushed
                        ? "Native IPv6 enabled (registry + live IOCTL)."
                        : "Native IPv6: registry OK, but \\\\.\\T2Ncm is unavailable.");
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                status = "No permission to write HKLM. Run the app as administrator.";
                return false;
            }
            catch (Exception ex)
            {
                status = "Error: " + ex.Message;
                return false;
            }
        }

        private void OnAutoSwitchChanged(object sender, RoutedEventArgs e)
        {
            if (_transportLoading) return;
            bool enabled = AutoSwitchCheck.IsChecked == true;
            bool ok = WriteAutoSwitch(enabled);
            if (!ok)
            {
                TransportStatusText.Text = "Could not write to HKLM (run the app as administrator).";
                TransportStatusText.Foreground = DotError;
                LoadTransportMode(); // revert the checkbox to what is really stored
                return;
            }
            LoadTransportMode();
            TransportStatusText.Text = enabled
                ? "Automatic fallback enabled. Applies from the next connection."
                : "Automatic fallback disabled. Applies from the next connection.";
            TransportStatusText.Foreground = DotOk;
        }

        private void OnTransportModeChanged(object sender, RoutedEventArgs e)
        {
            if (_transportLoading) return;
            bool tunnel = Ipv4TunnelCheck.IsChecked == true;
            bool ok = ApplyTransportCore(tunnel, out string status);
            TransportStatusText.Text = status;
            TransportStatusText.Foreground = ok ? DotOk : DotError;
        }

        private const uint IOCTL_T2NCM_SET_TRANSPORT_MODE = 0x0022A40C;
        private const uint IOCTL_T2NCM_SET_TUNNEL_PEER = 0x0022A408;
        private const uint IOCTL_T2NCM_SET_TUNNEL_LOCAL = 0x0022A410;
        private const string T2NcmDevicePath = @"\\.\T2Ncm";

        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint OPEN_EXISTING = 3;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
            uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            ref uint lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            byte[] lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static bool PushTransportModeToDriver(int mode)
        {
            IntPtr handle = CreateFileW(T2NcmDevicePath, GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                return false;
            try
            {
                uint value = (uint)mode;
                return DeviceIoControl(handle, IOCTL_T2NCM_SET_TRANSPORT_MODE,
                    ref value, sizeof(uint), IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private static bool PushPersistedPeerToDriver()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(NetworkRegPath, false);
                if (key?.GetValue(PeerIpv6Value) is not byte[] peer || peer.Length != 16)
                    return false;
                IntPtr handle = CreateFileW(T2NcmDevicePath, GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (handle == new IntPtr(-1))
                    return false;
                try
                {
                    return DeviceIoControl(handle, IOCTL_T2NCM_SET_TUNNEL_PEER,
                        peer, (uint)peer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero);
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool IsT2NcmAdapter(System.Net.NetworkInformation.NetworkInterface nic)
        {
            string d = nic.Description ?? "";
            string n = nic.Name ?? "";
            if (d.Contains("T2") && d.Contains("NCM")) return true;
            if (n.Contains("T2") && n.Contains("NCM")) return true;
            return d.Contains("UsbNcm") || n.Contains("UsbNcm") ||
                   d.Contains("Apple T2 USB NCM") || n.Contains("Apple T2 USB NCM");
        }

        // Read Windows' real link-local IPv6 on the T2 NCM adapter from the IP stack
        // (no network traffic, so it works while a VPN drops IPv6) and hand it to
        // T2Ncm.sys, which needs it as the source of every rewritten tunnel frame.
        private static bool PushLocalLinkLocalToDriver()
        {
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (!IsT2NcmAdapter(nic)) continue;
                    foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                    {
                        var a = ua.Address;
                        if (a.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 || !a.IsIPv6LinkLocal)
                            continue;
                        byte[] bytes = a.GetAddressBytes();
                        if (bytes.Length != 16) continue;
                        IntPtr handle = CreateFileW(T2NcmDevicePath, GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                        if (handle == new IntPtr(-1))
                            return false;
                        try
                        {
                            return DeviceIoControl(handle, IOCTL_T2NCM_SET_TUNNEL_LOCAL,
                                bytes, (uint)bytes.Length, IntPtr.Zero, 0, out _, IntPtr.Zero);
                        }
                        finally
                        {
                            CloseHandle(handle);
                        }
                    }
                }
            }
            catch
            {
                /* best-effort */
            }
            return false;
        }

        // Map last 4 bytes of fe80 to 169.254.x.y (same as MapPeerToIpv4 in TransportMode.h)
        // and fire a short non-blocking TCP connect so T2Ncm sees outbound tunnel frames.
        private static void WarmTunnelDatapathFromPersistedPeer()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(NetworkRegPath, false);
                if (key?.GetValue(PeerIpv6Value) is not byte[] peer || peer.Length != 16)
                    return;
                // in6_addr last 4 bytes at offset 12
                var ip = new System.Net.IPAddress(new byte[] { 169, 254, peer[14], peer[15] });
                using var client = new System.Net.Sockets.TcpClient();
                var ar = client.BeginConnect(ip, 1, null, null);
                ar.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(100));
                try { client.Close(); } catch { }
            }
            catch
            {
                /* best-effort */
            }
        }

        private void OnRefreshStatus(object sender, RoutedEventArgs e)
        {
            LoadSepStatus();
            LoadTransportMode();
        }

        // ---- Per-driver DebugView logging (HKLM\SOFTWARE\T2TouchId\Logging) ----
        private const string LogRegPath = @"SOFTWARE\T2TouchId\Logging";
        private bool _logFlagsLoading;

        private static bool ReadLogFlag(string name, bool defaultValue = false)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LogRegPath, writable: false);
                if (key == null) return defaultValue;
                object? v = key.GetValue(name);
                if (v is int i) return i != 0;
                if (v is long l) return l != 0;
                return defaultValue;
            }
            catch
            {
                return defaultValue;
            }
        }

        private static bool WriteLogFlag(string name, bool enabled)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(LogRegPath, true);
                if (key == null) return false;
                key.SetValue(name, enabled ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (System.Security.SecurityException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }

        private void LoadLogFlags()
        {
            _logFlagsLoading = true;
            try
            {
                LogPowerCheck.IsChecked = ReadLogFlag("Power");
                LogBioCheck.IsChecked = ReadLogFlag("Bio");
                LogBridgeCheck.IsChecked = ReadLogFlag("BridgeXpc");
                LogTransportCheck.IsChecked = ReadLogFlag("Transport");
                LogNcmCheck.IsChecked = ReadLogFlag("Ncm");
                LogStatusText.Text = "DebugView filter: T2TouchId* | T2Ncm* | t2touchid. Kernel logs (Transport/NCM) need Capture Kernel.";
                LogStatusText.Foreground = TextMuted;
            }
            finally
            {
                _logFlagsLoading = false;
            }
        }

        private void OnLogFlagChanged(object sender, RoutedEventArgs e)
        {
            if (_logFlagsLoading) return;

            bool ok =
                WriteLogFlag("Power", LogPowerCheck.IsChecked == true) &
                WriteLogFlag("Bio", LogBioCheck.IsChecked == true) &
                WriteLogFlag("BridgeXpc", LogBridgeCheck.IsChecked == true) &
                WriteLogFlag("Transport", LogTransportCheck.IsChecked == true) &
                WriteLogFlag("Ncm", LogNcmCheck.IsChecked == true);

            if (!ok)
            {
                LogStatusText.Text = "Could not write to HKLM (run the app as administrator).";
                LogStatusText.Foreground = DotError;
            }
            else
            {
                LogStatusText.Text = "Saved. UMDF/BridgeXpc pick it up immediately; kernel drivers after the next sleep or a driver reload.";
                LogStatusText.Foreground = DotOk;
            }
        }

        // ---- Short Verify (HKLM\SOFTWARE\T2TouchIdBio\ShortVerify) ----
        // Read by the UMDF driver (Queue.cpp, LoadShortVerify) before every
        // StartMatch attempt. Missing value = default ON (fast verification).
        private const string BioRegPath = @"SOFTWARE\T2TouchIdBio";
        private const string ShortVerifyValue = "ShortVerify";
        private bool _shortVerifyLoading;

        private static bool ReadShortVerify()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(BioRegPath, writable: false);
                object? v = key?.GetValue(ShortVerifyValue);
                if (v is int i) return i != 0;
                if (v is long l) return l != 0;
                // Missing value: default ON (fast verification).
                return true;
            }
            catch
            {
                return true;
            }
        }

        private static bool WriteShortVerify(bool enabled)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(BioRegPath, true);
                if (key == null) return false;
                key.SetValue(ShortVerifyValue, enabled ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void LoadShortVerify()
        {
            _shortVerifyLoading = true;
            try
            {
                ShortVerifyCheck.IsChecked = ReadShortVerify();
                ShortVerifyStatusText.Text = ShortVerifyCheck.IsChecked == true
                    ? "On: ResetSensor and LoadCalibration are skipped."
                    : "Off: full sequence (Linux parity).";
                ShortVerifyStatusText.Foreground = TextMuted;
            }
            finally
            {
                _shortVerifyLoading = false;
            }
        }

        private void OnShortVerifyChanged(object sender, RoutedEventArgs e)
        {
            if (_shortVerifyLoading) return;

            bool enabled = ShortVerifyCheck.IsChecked == true;
            if (!WriteShortVerify(enabled))
            {
                ShortVerifyStatusText.Text = "Could not write to HKLM (run the app as administrator).";
                ShortVerifyStatusText.Foreground = DotError;
                return;
            }
            ShortVerifyStatusText.Text = enabled
                ? "Saved: fast verification is on. Applies from the next verification session."
                : "Saved: full sequence. Applies from the next verification session.";
            ShortVerifyStatusText.Foreground = DotOk;
        }

        // ---- Lock on display-off (HKLM\SOFTWARE\T2TouchIdBio\LockOnDisplayOff) ----
        // Used by UMDF OnConsoleDisplayState(OFF).
        // Toggle ON  -> set PBUTTONACTION = 4 (Turn off the display) on ALL power schemes (AC+DC)
        //             and enable lock-on-display-off.
        // Toggle OFF -> set PBUTTONACTION = 1 (Sleep) on ALL power schemes (AC+DC)
        //             and disable lock-on-display-off.
        private const string LockOnDisplayOffValue = "LockOnDisplayOff";
        private const int PowerButtonDisplayOff = 4;
        private const int PowerButtonSleep = 1;
        private bool _lockOnDisplayOffLoading;

        private static int? QueryPowerButtonAction(string getCmd)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powercfg",
                Arguments = "/" + getCmd + " SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            string output = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(3000)) return null;
            // powercfg prints the index as the last integer token (decimal or hex).
            var tokens = output.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = tokens.Length - 1; i >= 0; i--)
            {
                if (int.TryParse(tokens[i], System.Globalization.NumberStyles.Integer,
                        System.Globalization.CultureInfo.InvariantCulture, out int v))
                    return v;
                if (int.TryParse(tokens[i], System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out v))
                    return v;
            }
            return null;
        }

        /// <summary>True when the active scheme has PBUTTONACTION = Turn off the display on AC or DC.</summary>
        private static bool IsPowerButtonDisplayOff()
        {
            try
            {
                int? ac = QueryPowerButtonAction("getacvalueindex");
                int? dc = QueryPowerButtonAction("getdcvalueindex");
                return ac == PowerButtonDisplayOff || dc == PowerButtonDisplayOff;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Enumerate all power scheme GUIDs from <c>powercfg /list</c>.</summary>
        private static List<string> ListPowerSchemeGuids()
        {
            var guids = new List<string>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powercfg",
                    Arguments = "/list",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var p = Process.Start(psi);
                if (p == null) return guids;
                string output = p.StandardOutput.ReadToEnd();
                if (!p.WaitForExit(5000)) return guids;

                // Lines look like: "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *"
                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int idx = line.IndexOf("GUID:", StringComparison.OrdinalIgnoreCase);
                    if (idx < 0) continue;
                    string rest = line.Substring(idx + 5).Trim();
                    int space = rest.IndexOfAny(new[] { ' ', '\t', '(' });
                    string guid = (space > 0 ? rest.Substring(0, space) : rest).Trim();
                    if (guid.Length == 36 && guid.Split('-').Length == 5)
                        guids.Add(guid);
                }
            }
            catch
            {
                // fall through with empty list
            }
            return guids;
        }

        /// <summary>
        /// Set PBUTTONACTION on every scheme for both AC and DC.
        /// index 4 = Turn off the display, index 1 = Sleep.
        /// Returns true if at least one scheme was updated successfully.
        /// </summary>
        private static bool SetPowerButtonActionOnAllSchemes(int index)
        {
            var schemes = ListPowerSchemeGuids();
            if (schemes.Count == 0)
            {
                // Fallback: only touch the active scheme.
                schemes.Add("SCHEME_CURRENT");
            }

            bool anyOk = false;
            foreach (string scheme in schemes)
            {
                if (RunPowerCfg($"/setacvalueindex {scheme} SUB_BUTTONS PBUTTONACTION {index}"))
                    anyOk = true;
                if (RunPowerCfg($"/setdcvalueindex {scheme} SUB_BUTTONS PBUTTONACTION {index}"))
                    anyOk = true;
            }

            // Re-apply active scheme so the change takes effect immediately.
            RunPowerCfg("/setactive SCHEME_CURRENT");
            return anyOk;
        }

        private static bool RunPowerCfg(string args)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powercfg",
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var p = Process.Start(psi);
                if (p == null) return false;
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                if (!p.WaitForExit(5000)) return false;
                return p.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool ReadLockOnDisplayOff()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(BioRegPath, writable: false);
                object? v = key?.GetValue(LockOnDisplayOffValue);
                return v is int i && i != 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool WriteLockOnDisplayOff(bool enabled)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(BioRegPath, true);
                if (key == null) return false;
                key.SetValue(LockOnDisplayOffValue, enabled ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void LoadLockOnDisplayOff()
        {
            _lockOnDisplayOffLoading = true;
            try
            {
                // Toggle is always available; it drives the power-button action itself.
                LockOnDisplayOffCheck.IsEnabled = true;
                bool want = ReadLockOnDisplayOff();
                // Prefer registry, but if registry is off and the live plan is already
                // display-off, still show the switch as on so the UI matches reality.
                bool liveDisplayOff = IsPowerButtonDisplayOff();
                LockOnDisplayOffCheck.IsChecked = want || liveDisplayOff;

                if (LockOnDisplayOffCheck.IsChecked == true)
                {
                    LockOnDisplayOffStatusText.Text =
                        "On: power button = Turn off the display (all plans). Display-off also locks the PC.";
                }
                else
                {
                    LockOnDisplayOffStatusText.Text =
                        "Off: power button = Sleep (all plans). No lock on display-off.";
                }
                LockOnDisplayOffStatusText.Foreground = TextMuted;
            }
            finally
            {
                _lockOnDisplayOffLoading = false;
            }
        }

        private void OnLockOnDisplayOffChanged(object sender, RoutedEventArgs e)
        {
            if (_lockOnDisplayOffLoading) return;

            bool enabled = LockOnDisplayOffCheck.IsChecked == true;
            int action = enabled ? PowerButtonDisplayOff : PowerButtonSleep;

            bool powerOk = SetPowerButtonActionOnAllSchemes(action);
            bool regOk = WriteLockOnDisplayOff(enabled);

            if (!powerOk && !regOk)
            {
                LockOnDisplayOffStatusText.Text =
                    "Could not change power settings or HKLM (run the app as administrator).";
                LockOnDisplayOffStatusText.Foreground = DotError;
                return;
            }

            if (!powerOk)
            {
                LockOnDisplayOffStatusText.Text =
                    "Registry saved, but powercfg failed (run as administrator to change all plans).";
                LockOnDisplayOffStatusText.Foreground = DotWarn;
                return;
            }

            if (!regOk)
            {
                LockOnDisplayOffStatusText.Text =
                    "Power button updated on all plans, but could not write HKLM (run as administrator).";
                LockOnDisplayOffStatusText.Foreground = DotWarn;
                return;
            }

            LockOnDisplayOffStatusText.Text = enabled
                ? "Saved: power button = Turn off the display (all plans) + lock on display-off."
                : "Saved: power button = Sleep (all plans). Lock on display-off off.";
            LockOnDisplayOffStatusText.Foreground = DotOk;
        }



        // Reads the driver's in-memory bootstrap status and updates the
        // banner. Never throws into the caller - every failure mode
        // (driver not loaded, IOCTL error) becomes a specific banner state
        // instead of a crash or a silent blank.
        private void LoadSepStatus()
        {
            SepHangPanel.Visibility = Visibility.Collapsed;

            try
            {
                SepBootstrapStatus status = SepStatusClient.GetStatus();
                ApplyStatus(status);
            }
            catch (SepDeviceNotFoundException)
            {
                SetBanner(DotError, "T2TouchIdTransport driver not found",
                    "Make sure the driver is installed and loaded (Device Manager).");
            }
            catch (Win32Exception ex)
            {
                SetBanner(DotError, "Could not read the SEP status",
                    $"Driver request failed: {ex.Message}");
            }
            catch (Exception ex)
            {
                SetBanner(DotError, "Could not read the SEP status", ex.Message);
            }
        }

        private void ApplyStatus(SepBootstrapStatus status)
        {
            string when = status.TimestampLocal is DateTime t ? $" ({t:HH:mm:ss})" : "";

            switch (status.ReasonValue)
            {
                case SepBootstrapReason.Ok:
                    SetBanner(DotOk, "SEP ready" + when,
                        "Touch ID was unlocked on this boot. Everything is working.");
                    break;

                case SepBootstrapReason.Unknown:
                    SetBanner(DotUnknown, "SEP status unknown",
                        "The T2SepBootstrap service has not reported in this session. Restart the computer or start the service manually.");
                    break;

                case SepBootstrapReason.VaultMissing:
                    SetBanner(DotWarn, "Setup required" + when,
                        "sep-vault.bin is missing or damaged. Fill in the form below and click \"Save\".");
                    break;

                case SepBootstrapReason.Dpapi:
                    SetBanner(DotWarn, "Could not decrypt the vault" + when,
                        "sep-vault.bin may have been copied from another computer. Run the import below again on this machine.");
                    break;

                case SepBootstrapReason.RegisterOolFailed:
                    SetBanner(DotError, "Driver / transport error" + when,
                        "The driver could not prepare communication with the SEP. Try restarting Windows; if that does not help, see C:\\LogSEP.txt.");
                    break;

                case SepBootstrapReason.SepHang:
                    SetBanner(DotError, "SEP is not responding" + when,
                        "The Apple Secure Enclave is not answering requests (hardware hang).");
                    SepHangPanel.Visibility = Visibility.Visible;
                    break;

                case SepBootstrapReason.SepRejected:
                    SetBanner(DotWarn, "SEP rejected the request" + when,
                        $"Step \"{StepLabel(status.StepValue)}\": wrong password or keybag (sep_status={status.SepStatus}). Repeat the import below with the correct data.");
                    break;

                default:
                    SetBanner(DotUnknown, "SEP status unknown", "");
                    break;
            }
        }

        private static string StepLabel(SepBootstrapStep step) => step switch
        {
            SepBootstrapStep.ReadVault => "reading vault",
            SepBootstrapStep.UnprotectKeybag => "decrypting keybag",
            SepBootstrapStep.UnprotectPassword => "decrypting password",
            SepBootstrapStep.RegisterOol => "register-ool",
            SepBootstrapStep.LoadKeybag => "load-keybag",
            SepBootstrapStep.SetSystemKeybag => "set-system-keybag",
            SepBootstrapStep.UnlockHandle => "unlock(handle)",
            SepBootstrapStep.UnlockSpecialBag => "unlock(special bag)",
            SepBootstrapStep.Ready => "ready",
            _ => "unknown step",
        };

        private void SetBanner(Brush dot, string title, string subtitle)
        {
            SepStatusDot.Background = dot;
            SepStatusHalo.Background = dot;
            SepStatusTitle.Text = title;
            SepStatusSubtitle.Text = subtitle;
        }

        // ---- macOS Keybag (sep-vault.bin) ----
        private void LoadVaultState()
        {
            bool present = false;
            try
            {
                present = File.Exists(VaultPath) && new FileInfo(VaultPath).Length > 0;
            }
            catch
            {
                present = false;
            }

            if (present)
            {
                VaultConfiguredPanel.Visibility = Visibility.Visible;
                VaultImportPanel.Visibility = Visibility.Collapsed;
                try
                {
                    var fi = new FileInfo(VaultPath);
                    VaultConfiguredHint.Text =
                        $"sep-vault.bin is present ({fi.Length} bytes, {fi.LastWriteTime:yyyy-MM-dd HH:mm}). " +
                        "T2SepBootstrap will use it on the next cold boot.";
                }
                catch
                {
                    VaultConfiguredHint.Text =
                        "sep-vault.bin is present. T2SepBootstrap will use it on the next cold boot.";
                }
            }
            else
            {
                VaultConfiguredPanel.Visibility = Visibility.Collapsed;
                VaultImportPanel.Visibility = Visibility.Visible;
            }
        }

        private void OnClearKeybag(object sender, RoutedEventArgs e)
        {
            try
            {
                if (File.Exists(VaultPath))
                    File.Delete(VaultPath);
                _keybagBytes = null;
                KeybagPathBox.Text = "";
                PasswordBox.Clear();
                VaultStatusText.Text = "";
                VaultStatusText.Foreground = DotError;
                LoadVaultState();
            }
            catch (Exception ex)
            {
                VaultConfiguredPanel.Visibility = Visibility.Collapsed;
                VaultImportPanel.Visibility = Visibility.Visible;
                VaultStatusText.Foreground = DotError;
                VaultStatusText.Text = $"Could not delete sep-vault.bin: {ex.Message}";
            }
        }

        private void OnBrowseKeybag(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select user.kb",
                Filter = "Keybag files (*.kb)|*.kb|All files (*.*)|*.*"
            };
            if (dialog.ShowDialog() != true) return;

            try
            {
                var bytes = File.ReadAllBytes(dialog.FileName);
                // Matches the bound already enforced kernel-side
                // (driver/T2TouchIdTransport/public.h / akstore.c reject
                // anything outside this range) — fail here with a clear
                // message instead of writing a vault that load-keybag will
                // reject on every future boot.
                if (bytes.Length == 0 || bytes.Length > 16000)
                {
                    VaultStatusText.Foreground = DotError;
                    VaultStatusText.Text = $"user.kb must be 1..16000 bytes; the selected file is {bytes.Length}.";
                    return;
                }
                _keybagBytes = bytes;
                KeybagPathBox.Text = dialog.FileName;
                VaultStatusText.Text = "";
            }
            catch (Exception ex)
            {
                VaultStatusText.Foreground = DotError;
                VaultStatusText.Text = $"Could not read the file: {ex.Message}";
            }
        }

        private void OnSave(object sender, RoutedEventArgs e)
        {
            if (_keybagBytes == null)
            {
                VaultStatusText.Foreground = DotError;
                VaultStatusText.Text = "Select a user.kb file first.";
                return;
            }
            if (!int.TryParse(SpecialBagBox.Text.Trim(), out int specialBag))
            {
                VaultStatusText.Foreground = DotError;
                VaultStatusText.Text = "Special bag ID must be an integer (e.g. -501).";
                return;
            }
            if (string.IsNullOrEmpty(PasswordBox.Password))
            {
                VaultStatusText.Foreground = DotError;
                VaultStatusText.Text = "Enter the password.";
                return;
            }

            try
            {
                SepVaultFormat.Write(VaultPath, _keybagBytes, PasswordBox.Password, specialBag);
                VaultStatusText.Foreground = DotOk;
                VaultStatusText.Text = $"Saved: {VaultPath}\nYou can delete the original user.kb; the vault does not keep it in plaintext.\nRestart Windows to apply.";
                _keybagBytes = null;
                KeybagPathBox.Text = "";
                LoadVaultState();
            }
            catch (Exception ex)
            {
                VaultStatusText.Foreground = DotError;
                VaultStatusText.Text = $"Could not save the vault: {ex.Message}\nIs the app running as administrator?";
            }
            finally
            {
                // Password lives in a WPF PasswordBox's internal SecureString
                // machinery either way, and .NET string immutability means
                // the plaintext string handed to Write() can't be scrubbed
                // from the managed heap from here — clearing the control's
                // own buffer is the one thing this method can actually do.
                PasswordBox.Clear();
            }
        }
    }
}