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
using System.Windows;
using System.Windows.Media;
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
        }

        private void OnRefreshStatus(object sender, RoutedEventArgs e) => LoadSepStatus();

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