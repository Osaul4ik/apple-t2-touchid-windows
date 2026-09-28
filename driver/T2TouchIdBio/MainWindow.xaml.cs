// SPDX-License-Identifier: GPL-2.0-only
// MainWindow.xaml.cs — SEP status + one-time keybag setup UI, design doc §9.1.
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
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace T2TouchId.SepVaultGui
{
    public partial class MainWindow : Window
    {
        private const string VaultPath = @"C:\ProgramData\T2TouchId\sep-vault.bin";
        private byte[]? _keybagBytes;

        private static readonly Brush DotUnknown = new SolidColorBrush(Color.FromRgb(0x9E, 0x9E, 0x9E));
        private static readonly Brush DotOk = new SolidColorBrush(Color.FromRgb(0x1E, 0x7B, 0x34));
        private static readonly Brush DotWarn = new SolidColorBrush(Color.FromRgb(0xB3, 0x8A, 0x00));
        private static readonly Brush DotError = new SolidColorBrush(Color.FromRgb(0xB3, 0x26, 0x1E));

        public MainWindow()
        {
            InitializeComponent();
            LoadSepStatus();
            LoadLogFlags();
            LoadTransportMode();
            LoadWarmupStatus();
            // Poll cold-boot warmup status while the window is open so the
            // user sees waiting-peer → warming → ok without manual refresh.
            var warmupTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            warmupTimer.Tick += (_, __) => LoadWarmupStatus();
            warmupTimer.Start();
        }


        // ---- Network transport mode ----
        // There used to be a SEPARATE, persistent override here
        // (HKLM\SOFTWARE\T2TouchId\Network\TransportMode, non-volatile) that
        // the checkbox wrote on its own, independently of the auto
        // probe/fallback cache Connection.cpp uses at runtime
        // (SessionRegPath\SkipNativeIpv6Probe, volatile). That let the two
        // disagree — e.g. a checked box surviving a reboot would silently
        // pin every future boot to the tunnel, fighting the "always try v6
        // first at cold boot" default. That override is gone: the checkbox
        // now reads/writes the exact same session flag Connection.cpp reads
        // (t2::transport::kSkipNativeIpv6ProbeValue in TransportMode.h) —
        // checking it has the same effect as a real NativeIpv6 probe failure
        // (skip straight to Ipv4Tunnel until the next unlock), and
        // unchecking it has the same effect as a probe success (try
        // NativeIpv6 again on the very next connect). Because the key is
        // volatile it never survives a reboot, matching that same default.
        private const string SessionRegPath = @"SOFTWARE\T2TouchId\Network\Session";
        private const string SkipNativeIpv6ProbeValue = "SkipNativeIpv6Probe";
        private const string ColdBootWarmupDoneValue = "ColdBootWarmupDone";
        private const string WarmupStatusValue = "WarmupStatus";
        private const string WarmupDetailValue = "WarmupDetail";
        private bool _transportLoading;

        private void LoadTransportMode()
        {
            _transportLoading = true;
            try
            {
                bool tunnel = false;
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(SessionRegPath, false);
                    if (key?.GetValue(SkipNativeIpv6ProbeValue) is int i)
                        tunnel = i != 0;
                }
                catch { /* default native - matches cold-boot default */ }
                Ipv4TunnelCheck.IsChecked = tunnel;
                TransportStatusText.Text = tunnel
                    ? "Режим цього сеансу: IPv4 tunnel (SkipNativeIpv6Probe=1)."
                    : "Режим цього сеансу: Native IPv6 (SkipNativeIpv6Probe не встановлено).";
                TransportStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x66, 0x66, 0x66));
            }
            finally
            {
                _transportLoading = false;
            }
        }


        private void LoadWarmupStatus()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(SessionRegPath, false);
                if (key == null)
                {
                    WarmupStatusText.Text = "idle — ще не було unlock після cold boot";
                    WarmupDetailText.Text = "";
                    return;
                }
                var done = key.GetValue(ColdBootWarmupDoneValue);
                var status = key.GetValue(WarmupStatusValue) as string;
                var detail = key.GetValue(WarmupDetailValue) as string;
                if (status == null || status.Length == 0)
                {
                    WarmupStatusText.Text = done is int i && i != 0
                        ? "done (статус не записано)"
                        : "idle — ще не було unlock після cold boot";
                    WarmupDetailText.Text = "";
                    return;
                }
                WarmupStatusText.Text = status;
                WarmupDetailText.Text = detail ?? "";
                if (status == "ok")
                    WarmupStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x2E, 0x7D, 0x32));
                else if (status != null && status.StartsWith("failed"))
                    WarmupStatusText.Foreground = DotError;
                else
                    WarmupStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x66, 0x66, 0x66));
            }
            catch
            {
                WarmupStatusText.Text = "(немає доступу до HKLM Session)";
                WarmupDetailText.Text = "";
            }
        }

        private void OnTransportModeChanged(object sender, RoutedEventArgs e)
        {
            if (_transportLoading) return;
            try
            {
                bool tunnel = Ipv4TunnelCheck.IsChecked == true;
                // RegistryOptions.Volatile matters only for the FIRST-EVER
                // creation of this key - if Connection.cpp already created it
                // (RecordNativeIpv6Failure, TransportMode.h) this just opens
                // the existing volatile key as-is. Without it, a GUI-first
                // creation would leave a plain (non-volatile) key behind that
                // DOES survive a reboot - exactly the bug this change removes.
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    SessionRegPath, RegistryKeyPermissionCheck.ReadWriteSubTree,
                    Microsoft.Win32.RegistryOptions.Volatile);
                if (key == null)
                    throw new UnauthorizedAccessException();
                if (tunnel)
                    key.SetValue(SkipNativeIpv6ProbeValue, 1, Microsoft.Win32.RegistryValueKind.DWord);
                else
                    key.DeleteValue(SkipNativeIpv6ProbeValue, throwOnMissingValue: false);

                // Push it into the already-running adapter too, via
                // IOCTL_T2NCM_SET_TRANSPORT_MODE, so toggling the checkbox
                // works immediately on the next connect attempt without
                // waiting for T2Ncm to reinitialize. 169.254.84.1 still needs
                // to be on the T2Ncm adapter for tunnel mode either way.
                bool pushedLive = PushTransportModeToDriver(tunnel ? 1 : 0);
                string liveNote = pushedLive
                    ? " Застосовано одразу."
                    : " Буде застосовано при наступному підключенні T2Ncm (драйвер зараз недоступний).";
                TransportStatusText.Text = (tunnel
                    ? "Цей сеанс: IPv4 tunnel. Додайте 169.254.84.1 на адаптер T2Ncm, якщо ще не додано."
                    : "Цей сеанс: Native IPv6 (спробується знову на наступному підключенні).") + liveNote
                    + " Скидається при перезавантаженні.";
                TransportStatusText.Foreground = DotOk;
            }
            catch (UnauthorizedAccessException)
            {
                TransportStatusText.Text = "Немає прав на HKLM — запустіть GUI від імені адміністратора.";
                TransportStatusText.Foreground = DotError;
            }
            catch (Exception ex)
            {
                TransportStatusText.Text = "Помилка запису: " + ex.Message;
                TransportStatusText.Foreground = DotError;
            }
        }

        // ---- Live push to the running T2Ncm.sys (\\.\T2Ncm) ----
        // IOCTL_T2NCM_SET_TRANSPORT_MODE = CTL_CODE(FILE_DEVICE_UNKNOWN=0x22,
        // 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS) — computed the same way
        // public.h's CTL_CODE macro does, same one-literal approach
        // SepStatusClient.cs already uses for IOCTL_T2_GET_BOOTSTRAP_STATUS.
        // T2Ncm.sys is reached through a fixed symbolic link
        // (T2NCM_USER_DEVICE_PATH in public.h), not a device interface GUID,
        // so this needs no SetupDi enumeration — just CreateFileW it directly.
        private const uint IOCTL_T2NCM_SET_TRANSPORT_MODE = 0x0022A40C;
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
        private static extern bool CloseHandle(IntPtr hObject);

        // Returns false (never throws) whenever T2Ncm.sys isn't loaded/the
        // adapter isn't present right now — the registry write above is
        // what matters for correctness; this is best-effort immediacy on
        // top of it, same "don't block the setting on the device being
        // there" shape as PushTunnelPeerToDriver in TransportMode.h.
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


        private void OnRefreshStatus(object sender, RoutedEventArgs e)
        {
            LoadSepStatus();
            LoadTransportMode();
            LoadWarmupStatus();
        }

        // ---- Per-driver DebugView logging (HKLM\SOFTWARE\T2TouchId\Logging) ----
        private const string LogRegPath = @"SOFTWARE\T2TouchId\Logging";
        private bool _logFlagsLoading;

        private static bool ReadLogFlag(string name, bool defaultValue = true)
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
                LogStatusText.Text = "Фільтр DebugView: T2TouchId* | T2Ncm* | t2touchid. Kernel: Capture Kernel для Transport/NCM.";
                LogStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x66, 0x66, 0x66));
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
                LogStatusText.Text = "Не вдалось записати HKLM (запустіть GUI від імені адміністратора).";
                LogStatusText.Foreground = DotError;
            }
            else
            {
                LogStatusText.Text = "Збережено. UMDF/BridgeXpc підхоплять одразу; kernel — після наступного sleep або перезавантаження драйвера.";
                LogStatusText.Foreground = DotOk;
            }
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
                SetBanner(DotError, "Драйвер T2TouchIdTransport не знайдено",
                    "Переконайтесь, що драйвер встановлено і завантажено (Диспетчер пристроїв).");
            }
            catch (Win32Exception ex)
            {
                SetBanner(DotError, "Не вдалось прочитати стан SEP",
                    $"Помилка звернення до драйвера: {ex.Message}");
            }
            catch (Exception ex)
            {
                SetBanner(DotError, "Не вдалось прочитати стан SEP", ex.Message);
            }
        }

        private void ApplyStatus(SepBootstrapStatus status)
        {
            string when = status.TimestampLocal is DateTime t ? $" ({t:HH:mm:ss})" : "";

            switch (status.ReasonValue)
            {
                case SepBootstrapReason.Ok:
                    SetBanner(DotOk, "SEP готовий" + when,
                        "Touch ID розблоковано цього завантаження — усе працює.");
                    break;

                case SepBootstrapReason.Unknown:
                    SetBanner(DotUnknown, "Стан SEP невідомий",
                        "Сервіс T2SepBootstrap ще не звітував цього сеансу — перезавантажте комп'ютер або запустіть сервіс вручну.");
                    break;

                case SepBootstrapReason.VaultMissing:
                    SetBanner(DotWarn, "Потрібне налаштування" + when,
                        "sep-vault.bin відсутній або пошкоджений. Заповніть форму нижче і натисніть «Зберегти».");
                    break;

                case SepBootstrapReason.Dpapi:
                    SetBanner(DotWarn, "Не вдалось розшифрувати vault" + when,
                        "Можливо, sep-vault.bin скопійовано з іншого комп'ютера. Запустіть імпорт нижче ще раз на цій машині.");
                    break;

                case SepBootstrapReason.RegisterOolFailed:
                    SetBanner(DotError, "Помилка драйвера/транспорту" + when,
                        "Не вдалось підготувати обмін із SEP на рівні драйвера. Спробуйте перезавантажити Windows; якщо не допоможе — дивіться C:\\LogSEP.txt.");
                    break;

                case SepBootstrapReason.SepHang:
                    SetBanner(DotError, "SEP не відповідає" + when,
                        "Apple Secure Enclave не відповідає на запити (апаратне зависання).");
                    SepHangPanel.Visibility = Visibility.Visible;
                    break;

                case SepBootstrapReason.SepRejected:
                    SetBanner(DotWarn, "SEP відхилив запит" + when,
                        $"Крок «{StepLabel(status.StepValue)}»: неправильний пароль або keybag (sep_status={status.SepStatus}). Повторіть імпорт нижче з коректними даними.");
                    break;

                default:
                    SetBanner(DotUnknown, "Стан SEP невідомий", "");
                    break;
            }
        }

        private static string StepLabel(SepBootstrapStep step) => step switch
        {
            SepBootstrapStep.ReadVault => "читання vault",
            SepBootstrapStep.UnprotectKeybag => "розшифрування keybag",
            SepBootstrapStep.UnprotectPassword => "розшифрування пароля",
            SepBootstrapStep.RegisterOol => "register-ool",
            SepBootstrapStep.LoadKeybag => "load-keybag",
            SepBootstrapStep.SetSystemKeybag => "set-system-keybag",
            SepBootstrapStep.UnlockHandle => "unlock(handle)",
            SepBootstrapStep.UnlockSpecialBag => "unlock(special bag)",
            SepBootstrapStep.Ready => "готово",
            _ => "невідомий крок",
        };

        private void SetBanner(Brush dot, string title, string subtitle)
        {
            SepStatusDot.Background = dot;
            SepStatusTitle.Text = title;
            SepStatusSubtitle.Text = subtitle;
        }

        private void OnBrowseKeybag(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Обрати user.kb",
                Filter = "Keybag files (*.kb)|*.kb|Усі файли (*.*)|*.*"
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
                    VaultStatusText.Foreground = Brushes.DarkRed;
                    VaultStatusText.Text = $"user.kb має бути 1..16000 байт, обраний файл — {bytes.Length}.";
                    return;
                }
                _keybagBytes = bytes;
                KeybagPathBox.Text = dialog.FileName;
                VaultStatusText.Text = "";
            }
            catch (Exception ex)
            {
                VaultStatusText.Foreground = Brushes.DarkRed;
                VaultStatusText.Text = $"Не вдалось прочитати файл: {ex.Message}";
            }
        }

        private void OnSave(object sender, RoutedEventArgs e)
        {
            if (_keybagBytes == null)
            {
                VaultStatusText.Foreground = Brushes.DarkRed;
                VaultStatusText.Text = "Спочатку оберіть user.kb.";
                return;
            }
            if (!int.TryParse(SpecialBagBox.Text.Trim(), out int specialBag))
            {
                VaultStatusText.Foreground = Brushes.DarkRed;
                VaultStatusText.Text = "Special bag id має бути цілим числом (напр. -501).";
                return;
            }
            if (string.IsNullOrEmpty(PasswordBox.Password))
            {
                VaultStatusText.Foreground = Brushes.DarkRed;
                VaultStatusText.Text = "Введіть пароль.";
                return;
            }

            try
            {
                SepVaultFormat.Write(VaultPath, _keybagBytes, PasswordBox.Password, specialBag);
                VaultStatusText.Foreground = Brushes.DarkGreen;
                VaultStatusText.Text = $"Збережено: {VaultPath}\nОригінальний user.kb можна видалити — vault не тримає його в plaintext.\nПерезавантажте Windows, щоб застосувати.";
            }
            catch (Exception ex)
            {
                VaultStatusText.Foreground = Brushes.DarkRed;
                VaultStatusText.Text = $"Не вдалось зберегти vault: {ex.Message}\nЗапущено з правами адміністратора?";
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