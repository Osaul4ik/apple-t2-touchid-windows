// SPDX-License-Identifier: GPL-2.0-only
using System;
using System.Linq;
using System.Windows;

namespace T2TouchId.SepVaultGui
{
    public partial class App : Application
    {
        // cmd examples:
        //   SepVaultGui.exe --auto | --no-auto   (persistent IPv6->IPv4 auto-switch, default on)
        //   SepVaultGui.exe --no-auto --quit
        // There is no way to force IPv4: the switch is automatic and lasts until reboot.
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            var args = e.Args.Select(a => a.Trim().ToLowerInvariant()).ToArray();
            bool quit = args.Any(a => a is "--quit" or "/quit" or "-q");
            bool autoOn = args.Any(a => a is "--auto" or "/auto");
            bool autoOff = args.Any(a => a is "--no-auto" or "/no-auto");

            if (autoOn != autoOff)
            {
                bool okAuto = T2TouchId.SepVaultGui.MainWindow.ApplyAutoSwitchFromCommandLine(autoOn);
                if (quit)
                {
                    Environment.Exit(okAuto ? 0 : 1);
                    return;
                }
            }

            var window = new T2TouchId.SepVaultGui.MainWindow();
            if (autoOn != autoOff)
            {
                window.RefreshTransportUi();
            }
            window.Show();
        }
    }
}