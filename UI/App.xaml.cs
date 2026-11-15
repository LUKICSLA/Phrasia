using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;
using NLog;

namespace Phrasia;

/// <summary>WPF application entry point: configures logging and global exception handling.</summary>
public partial class App : Application
{
    private static readonly Logger Log = LogManager.GetLogger("Phrasia.App");

    /// <summary>Initializes logging, installs global exception handlers, then starts the app.</summary>
    protected override void OnStartup(StartupEventArgs e)
    {
        Logging.Configure();
        Log.Info("Phrasia {Version} starting · {OS} · {Runtime} · {Arch}",
            Phrasia.MainWindow.AppVersion, RuntimeInformation.OSDescription,
            RuntimeInformation.FrameworkDescription, RuntimeInformation.ProcessArchitecture);

        // Unhandled errors: log them and show a readable message instead of crashing silently.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            Log.Fatal(args.ExceptionObject as Exception, "Unhandled exception (terminating: {Terminating})", args.IsTerminating);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            Log.Error(args.Exception, "Unobserved task exception");
            args.SetObserved();
        };

        base.OnStartup(e);
    }

    /// <summary>Logs an unhandled UI-thread exception, shows a message, and keeps the app running.</summary>
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.Error(e.Exception, "Unhandled UI exception");
        AppMessageBox.Show(
            "Something went wrong:\n" + e.Exception.Message +
            "\n\nThe details were written to the log file:\n" + Logging.LogDirectory,
            "Phrasia", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true; // keep the app alive
    }

    /// <summary>Flushes and closes the log on exit.</summary>
    protected override void OnExit(ExitEventArgs e)
    {
        Log.Info("Phrasia exiting (code {Code})", e.ApplicationExitCode);
        LogManager.Shutdown(); // flush and close the log
        base.OnExit(e);
    }
}
