// SPDX-License-Identifier: GPL-2.0-only
using System;
using System.Linq;
using System.Windows;

namespace T2TouchId.SepVaultGui
{
    public partial class App : Application
    {
        // cmd examples:
        //   SepVaultGui.exe --tunnel
        //   SepVaultGui.exe --native
        //   SepVaultGui.exe --tunnel --quit
        //   SepVaultGui.exe --auto  | --no-auto   (persistent IPv6->IPv4 auto-switch, default on)
        //   SepVaultGui.exe /tunnel /quit
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            var args = e.Args.Select(a => a.Trim().ToLowerInvariant()).ToArray();
            bool tunnel = args.Any(a => a is "--tunnel" or "/tunnel" or "--ipv4" or "/ipv4");
            bool native = args.Any(a => a is "--native" or "/native" or "--ipv6" or "/ipv6");
            bool quit = args.Any(a => a is "--quit" or "/quit" or "-q");
            bool autoOn = args.Any(a => a is "--auto" or "/auto");
            bool autoOff = args.Any(a => a is "--no-auto" or "/no-auto");

            if (autoOn != autoOff)
            {
                bool okAuto = T2TouchId.SepVaultGui.MainWindow.ApplyAutoSwitchFromCommandLine(autoOn);
                if (quit && !(tunnel || native))
                {
                    Environment.Exit(okAuto ? 0 : 1);
                    return;
                }
            }

            if (tunnel || native)
            {
                // Fully qualify: App.MainWindow is a Window property and would
                // shadow the MainWindow class name.
                bool result = T2TouchId.SepVaultGui.MainWindow.ApplyTransportFromCommandLine(
                    tunnel: tunnel && !native);
                if (quit)
                {
                    Environment.Exit(result ? 0 : 1);
                    return;
                }
            }

            var window = new T2TouchId.SepVaultGui.MainWindow();
            if (tunnel || native || autoOn != autoOff)
            {
                window.RefreshTransportUi();
            }
            window.Show();
        }
    }
}