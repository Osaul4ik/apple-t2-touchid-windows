// SPDX-License-Identifier: GPL-2.0-only
// MainWindow.xaml.cs — one-time setup UI, design doc §9.1.
//
// Deliberately does NOT talk to protocol/AppleKeyStore or the SEP at all —
// this tool only ever produces sep-vault.bin. Verifying the password/keybag
// actually unlock the SEP happens the first time T2SepBootstrap runs on the
// next boot, and its failures land in C:\LogSEP.txt (see the service's
// Log() calls) rather than here, since this process never has device access
// or SEP context to validate against.

using System;
using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace T2TouchId.SepVaultGui
{
    public partial class MainWindow : Window
    {
        private const string VaultPath = @"C:\ProgramData\T2TouchId\sep-vault.bin";
        private byte[]? _keybagBytes;

        public MainWindow()
        {
            InitializeComponent();
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
                    StatusText.Text = $"user.kb має бути 1..16000 байт, обраний файл — {bytes.Length}.";
                    return;
                }
                _keybagBytes = bytes;
                KeybagPathBox.Text = dialog.FileName;
                StatusText.Text = "";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Не вдалось прочитати файл: {ex.Message}";
            }
        }

        private void OnSave(object sender, RoutedEventArgs e)
        {
            if (_keybagBytes == null)
            {
                StatusText.Text = "Спочатку оберіть user.kb.";
                return;
            }
            if (!int.TryParse(SpecialBagBox.Text.Trim(), out int specialBag))
            {
                StatusText.Text = "Special bag id має бути цілим числом (напр. -501).";
                return;
            }
            if (string.IsNullOrEmpty(PasswordBox.Password))
            {
                StatusText.Text = "Введіть пароль.";
                return;
            }

            try
            {
                SepVaultFormat.Write(VaultPath, _keybagBytes, PasswordBox.Password, specialBag);
                StatusText.Foreground = System.Windows.Media.Brushes.DarkGreen;
                StatusText.Text = $"Збережено: {VaultPath}\nОригінальний user.kb можна видалити — vault не тримає його в plaintext.";
            }
            catch (Exception ex)
            {
                StatusText.Foreground = System.Windows.Media.Brushes.DarkRed;
                StatusText.Text = $"Не вдалось зберегти vault: {ex.Message}\nЗапущено з правами адміністратора?";
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