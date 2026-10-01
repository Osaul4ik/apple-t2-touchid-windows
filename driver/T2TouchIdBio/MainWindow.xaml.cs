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
// either. Free-text detail beyond the summary shown here is only available
// as DebugView output of T2SepBootstrap (enable the SEP logging switch).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
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
            LoadBridgeCache();
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


        // ---- Network transport (automatic only) ----
        // Auto-switch (persistent): HKLM\SOFTWARE\T2TouchId\Network\AutoSwitch, DWORD, missing == ON.
        // Native IPv6 first; if it does not work the connection switches to the IPv4 tunnel and
        // stays there until reboot (volatile Session\AutoTunnelSticky, written by the service).
        // There is no manual "force IPv4".
        private const string SessionRegPath = @"SOFTWARE\T2TouchId\Network\Session";
        private const string NetworkRegPath = @"SOFTWARE\T2TouchId\Network";
        private const string AutoSwitchValue = "AutoSwitch";
        private const string AutoTunnelStickyValue = "AutoTunnelSticky";
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
                return true;
            }
            catch { return false; }
        }

        private static bool ReadTunnelSticky()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(SessionRegPath, false);
                return key?.GetValue(AutoTunnelStickyValue) is int i && i != 0;
            }
            catch { return false; }
        }

        /// <summary>Set the persistent auto-switch flag from the command line.</summary>
        public static bool ApplyAutoSwitchFromCommandLine(bool enabled) => WriteAutoSwitch(enabled);

        private void LoadTransportMode()
        {
            _transportLoading = true;
            try
            {
                bool auto = ReadAutoSwitch();
                bool sticky = auto && ReadTunnelSticky();
                AutoSwitchCheck.IsChecked = auto;
                TransportStatusText.Text = !auto
                    ? "Mode: Native IPv6 only (automatic switch is off)."
                    : sticky
                        ? "Mode: IPv4 tunnel. IPv6 was not working, so the connection switched automatically; it stays on IPv4 until the next reboot."
                        : "Mode: automatic. Native IPv6; if it does not work, the connection switches to the IPv4 tunnel until the next reboot.";
                TransportStatusText.Foreground = TextMuted;
            }
            finally
            {
                _transportLoading = false;
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
                ? "Automatic switch enabled. Applies from the next connection."
                : "Automatic switch disabled: Native IPv6 only. Applies from the next connection.";
            TransportStatusText.Foreground = DotOk;
        }

        private void OnRefreshStatus(object sender, RoutedEventArgs e)
        {
            LoadSepStatus();
            LoadTransportMode();
            LoadBridgeCache();
        }

        // ---- BridgeXPC card: port cache + `network` / `verify` via t2touchid.exe ----
        // The cache is read straight from the registry (same format PortCache.cpp writes:
        // one REG_SZ per adapter MAC, "bridgePort[,rsdPort]"). Rescan and the fingerprint
        // test run the CLI (t2touchid.exe next to this exe, else on PATH) and report what
        // it really printed - nothing here is reported as success unless the CLI said so.
        private const string PortCacheRegPath = NetworkRegPath + @"\PortCache";
        private const string CliName = "t2touchid.exe";
        private static readonly Brush BgOk = new SolidColorBrush(Color.FromRgb(0xF0, 0xFD, 0xF4));
        private static readonly Brush BgWarn = new SolidColorBrush(Color.FromRgb(0xFE, 0xF3, 0xC7));
        private static readonly Brush BgError = new SolidColorBrush(Color.FromRgb(0xFE, 0xF2, 0xF2));
        private static readonly Brush BgNeutral = new SolidColorBrush(Color.FromRgb(0xF9, 0xFA, 0xFB));
        private bool _bridgeBusy;
        private int _verifiedBridgePort; // set only after a live BridgeXPC HELO from this GUI session

        private readonly record struct PortCacheEntry(string Mac, int Port, int RsdPort);

        private static List<PortCacheEntry> ReadPortCache()
        {
            var list = new List<PortCacheEntry>();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PortCacheRegPath, false);
                if (key == null) return list;
                foreach (string name in key.GetValueNames())
                {
                    if (key.GetValue(name) is not string raw) continue;
                    string[] parts = raw.Split(',');
                    if (!int.TryParse(parts[0].Trim(), out int port) || port <= 0 || port > 65535) continue;
                    int rsd = 0;
                    if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int r) && r > 0 && r <= 65535)
                        rsd = r;
                    list.Add(new PortCacheEntry(name, port, rsd));
                }
            }
            catch { /* unreadable == no cache */ }
            return list;
        }

        private void SetBridgeDot(Brush brush)
        {
            BridgeStatusDot.Background = brush;
            BridgeStatusHalo.Background = brush;
        }

        private void LoadBridgeCache()
        {
            var entries = ReadPortCache();
            if (entries.Count == 0)
            {
                SetBridgeDot(DotUnknown);
                BridgeStatusTitle.Text = "No cached port";
                BridgeStatusSubtitle.Text =
                    "No entry in HKLM\\" + PortCacheRegPath + ". The next connection (or Rescan) runs a full port scan.";
                return;
            }

            // A PortCache entry is only ever written after a live BridgeXPC HELO succeeded
            // (SaveCachedPort), so an existing entry is a good port: green.
            bool verified = _verifiedBridgePort != 0 && entries.Any(en => en.Port == _verifiedBridgePort);
            SetBridgeDot(DotOk);
            BridgeStatusTitle.Text = entries.Count == 1
                ? $"Cached port: {entries[0].Port}"
                : $"{entries.Count} cached adapters";
            BridgeStatusSubtitle.Text =
                string.Join("\n", entries.Select(en =>
                    $"{en.Mac}  →  BridgeXPC {en.Port}" + (en.RsdPort != 0 ? $", RemoteXPC {en.RsdPort}" : "")))
                + (verified ? "\nRe-checked just now (BridgeXPC HELO OK)." : "");
        }

        private static string? FindCli()
        {
            try
            {
                string local = Path.Combine(AppContext.BaseDirectory, CliName);
                if (File.Exists(local)) return local;
                string path = Environment.GetEnvironmentVariable("PATH") ?? "";
                foreach (string dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                {
                    try
                    {
                        string candidate = Path.Combine(dir.Trim().Trim('"'), CliName);
                        if (File.Exists(candidate)) return candidate;
                    }
                    catch { /* malformed PATH entry */ }
                }
            }
            catch { }
            return null;
        }

        private sealed record CliResult(int ExitCode, bool TimedOut, List<string> Lines);

        private static async Task<CliResult> RunCliAsync(string exe, string args, TimeSpan timeout)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = new Process { StartInfo = psi };
            p.Start();
            Task<string> outTask = p.StandardOutput.ReadToEndAsync();
            Task<string> errTask = p.StandardError.ReadToEndAsync();
            Task exitTask = p.WaitForExitAsync();

            bool timedOut = false;
            if (await Task.WhenAny(exitTask, Task.Delay(timeout)) != exitTask)
            {
                timedOut = true;
                try { p.Kill(true); } catch { }
                await exitTask;
            }

            string text = await outTask + "\n" + await errTask;
            // The scan prints \r-terminated progress ("scanned N/M ..."); drop those.
            var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(l => l.Trim())
                            .Where(l => l.Length > 0 && !l.StartsWith("scanned ", StringComparison.Ordinal))
                            .ToList();
            return new CliResult(timedOut ? -1 : p.ExitCode, timedOut, lines);
        }

        private static string FailureReason(CliResult r, string fallback)
        {
            if (r.TimedOut) return "Timed out - the command was cancelled.";
            string[] markers =
            {
                "no T2 NCM adapter", "no Preferred IPv6", "no peer to scan", "no TCP listeners",
                "BiometricKit service not advertised", "BridgeXPC connect/HELO failed",
                "getBridgeVersion failed", "note:", "verify-failed", "failed",
            };
            foreach (string m in markers)
            {
                string? hit = r.Lines.FirstOrDefault(l => l.Contains(m, StringComparison.OrdinalIgnoreCase));
                if (hit != null) return hit;
            }
            return r.Lines.Count > 0 ? r.Lines[^1] : $"{fallback} (exit code {r.ExitCode}).";
        }

        private void SetBridgeBusy(bool busy)
        {
            _bridgeBusy = busy;
            BridgeRescanButton.IsEnabled = !busy;
            VerifyButton.IsEnabled = !busy;
        }

        private void ShowBridgeScan(string text, Brush fg)
        {
            BridgeScanText.Text = text;
            BridgeScanText.Foreground = fg;
            BridgeScanText.Visibility = Visibility.Visible;
        }

        private void ShowVerifyResult(string text, Brush fg, Brush bg)
        {
            VerifyResultText.Text = text;
            VerifyResultText.Foreground = fg;
            VerifyResultPanel.Background = bg;
            VerifyResultPanel.Visibility = Visibility.Visible;
        }

        private static readonly Regex BridgePortRx =
            new(@"BiometricKit BridgeXPC port:\s*(\d+)", RegexOptions.Compiled);
        private static readonly Regex BridgeVersionRx =
            new(@"bridge version=(-?\d+)", RegexOptions.Compiled);

        private async void OnBridgeRescan(object sender, RoutedEventArgs e)
        {
            if (_bridgeBusy) return;
            string? cli = FindCli();
            if (cli == null)
            {
                ShowBridgeScan($"{CliName} not found next to the GUI or on PATH.", DotError);
                return;
            }

            SetBridgeBusy(true);
            ShowBridgeScan("Scanning the T2 for the BridgeXPC port. This can take a while (longer in IPv4 tunnel mode)...", TextMuted);
            try
            {
                // --rescan: skip the cached port, scan, verify with a live HELO, then cache it.
                CliResult r = await RunCliAsync(cli, "network --rescan", TimeSpan.FromMinutes(5));

                int port = 0;
                foreach (string line in r.Lines)
                {
                    var m = BridgePortRx.Match(line);
                    if (m.Success) int.TryParse(m.Groups[1].Value, out port);
                }
                bool verified = r.Lines.Any(l => l.Contains("BridgeXPC verified: HELO OK", StringComparison.Ordinal));

                if (verified && port > 0)
                {
                    _verifiedBridgePort = port;
                    string? ver = r.Lines.Select(l => BridgeVersionRx.Match(l)).FirstOrDefault(m => m.Success)?.Groups[1].Value;
                    string msg = $"Port {port} found, BridgeXPC HELO OK" + (ver != null ? $" (bridge version {ver})" : "") + ". Cached.";
                    // An older t2touchid.exe ignores --rescan and answers from the cache.
                    if (r.Lines.Any(l => l.Contains("cached - skipped port scan", StringComparison.Ordinal)))
                        msg += " Note: this t2touchid.exe has no --rescan, so the port was re-checked from the cache without a new scan.";
                    ShowBridgeScan(msg, DotOk);
                }
                else
                {
                    _verifiedBridgePort = 0;
                    ShowBridgeScan("Rescan failed: " + FailureReason(r, "No BridgeXPC port confirmed"), DotError);
                }
            }
            catch (Exception ex)
            {
                _verifiedBridgePort = 0;
                ShowBridgeScan($"Could not run {CliName}: {ex.Message}", DotError);
            }
            finally
            {
                SetBridgeBusy(false);
                LoadBridgeCache();
            }
        }

        private async void OnVerifyFingerprint(object sender, RoutedEventArgs e)
        {
            if (_bridgeBusy) return;
            string? cli = FindCli();
            if (cli == null)
            {
                ShowVerifyResult($"{CliName} not found next to the GUI or on PATH.", DotError, BgError);
                return;
            }

            SetBridgeBusy(true);
            ShowVerifyResult("Place your finger on the sensor (lift and place it again if nothing happens)...", TextMuted, BgNeutral);
            try
            {
                CliResult r = await RunCliAsync(cli, "verify --seconds 15", TimeSpan.FromMinutes(5));
                bool Has(string s) => r.Lines.Any(l => l.StartsWith(s, StringComparison.Ordinal));

                if (r.TimedOut)
                    ShowVerifyResult("No answer: the command did not finish and was cancelled.", DotError, BgError);
                else if (Has("verify-match"))
                    ShowVerifyResult("Fingerprint read: match.", DotOk, BgOk);
                else if (Has("verify-no-match"))
                    ShowVerifyResult("Fingerprint read, but it is not an enrolled finger (wrong finger).", DotWarn, BgWarn);
                else if (Has("verify-timeout"))
                    ShowVerifyResult("No answer from the sensor: no match result arrived in time. Touch the sensor and try again.", DotError, BgError);
                else if (Has("verify-cancelled"))
                    ShowVerifyResult("Verification was cancelled.", DotWarn, BgWarn);
                else
                    ShowVerifyResult("Test failed: " + FailureReason(r, "No result from verify"), DotError, BgError);
            }
            catch (Exception ex)
            {
                ShowVerifyResult($"Could not run {CliName}: {ex.Message}", DotError, BgError);
            }
            finally
            {
                SetBridgeBusy(false);
                LoadBridgeCache(); // a successful verify may have created/refreshed the cache entry
            }
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
                LogStatusText.Text = "DebugView filter: T2TouchId* | T2Ncm* | t2touchid. Kernel logs (SEP driver / NCM) need Capture Kernel.";
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
                LogStatusText.Text = "Saved. User-mode parts (Bio, BridgeXPC, SEP bootstrap) pick it up within ~2 s; kernel drivers after the next sleep/resume or a driver reload.";
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
                        "The driver could not prepare communication with the SEP. Try restarting Windows; if that does not help, enable SEP logging (Developer tools) and check DebugView.");
                    break;

                case SepBootstrapReason.SepHang:
                    SetBanner(DotError, "SEP is not responding" + when,
                        "The Apple Secure Enclave is not answering requests (hardware hang).");
                    SepHangPanel.Visibility = Visibility.Visible;
                    break;

                case SepBootstrapReason.SepRejected:
                    SetBanner(DotWarn, "SEP rejected the request" + when,
                        $"Step \"{StepLabel(status.StepValue)}\": " +
                        (status.SepStatus != 0
                            ? $"the SEP refused the request (sep_status={status.SepStatus}): wrong keybag/handle or password. "
                            : "the SEP answered but rejected the secret (result code in the reply, not a mailbox error): wrong password or keybag. ") +
                        "Repeat the import below with the correct data.");
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