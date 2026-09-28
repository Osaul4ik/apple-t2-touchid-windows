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
                // Apply before/without requiring the window to be interactive.
                var result = MainWindow.ApplyTransportFromCommandLine(tunnel: tunnel && !native);
                if (quit)
                {
                    // Non-zero if apply failed (no admin / no T2Ncm).
                    Environment.Exit(result ? 0 : 1);
                    return;
                }
            }

            var window = new MainWindow();
            if (tunnel || native)
            {
                // Refresh UI to match what we just applied.
                window.RefreshTransportUi();
            }
            window.Show();
        }
    }
}
