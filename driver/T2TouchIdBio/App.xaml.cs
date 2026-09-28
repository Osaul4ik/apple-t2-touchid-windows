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
        //   SepVaultGui.exe /tunnel /quit
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            var args = e.Args.Select(a => a.Trim().ToLowerInvariant()).ToArray();
            bool tunnel = args.Any(a => a is "--tunnel" or "/tunnel" or "--ipv4" or "/ipv4");
            bool native = args.Any(a => a is "--native" or "/native" or "--ipv6" or "/ipv6");
            bool quit = args.Any(a => a is "--quit" or "/quit" or "-q");

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
            if (tunnel || native)
            {
                window.RefreshTransportUi();
            }
            window.Show();
        }
    }
}
