using System;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;

namespace SharpPress.Services
{
    public class Logger
    {
        private readonly string _logsFolder;
        private readonly string _logFile;
        private readonly object _logLock = new();

        private static readonly object _prepareLock = new object();

        public Logger(string logsFolder = "logs")
        {
            _logsFolder = logsFolder;
            _logFile = Path.Combine(_logsFolder, "latest.log");
        }

        public void PrepareLogs()
        {
            lock (_prepareLock)
            {
                try
                {
                    if (!Directory.Exists(_logsFolder)) Directory.CreateDirectory(_logsFolder);

                    if (File.Exists(_logFile))
                    {
                        string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                        string zipFile = Path.Combine(_logsFolder, $"latest_{timestamp}.zip");

                        using (var archive = ZipFile.Open(zipFile, ZipArchiveMode.Create))
                        {
                            archive.CreateEntryFromFile(_logFile, "latest.log");
                        }

                        File.Delete(_logFile);

                        File.WriteAllText(_logFile, string.Empty);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error preparing logs: {ex.Message}");
                }
            }
        }

        public void Log(string message) => WriteLog("INFO", message);
        public void LogError(string message) => WriteLog("ERROR", message);
        public void LogWarning(string message) => WriteLog("WARNING", message);
        public void LogSecurity(string message) => WriteLog("SECURITY", message);

        private void WriteLog(string level, string message)
        {
            string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
            Console.WriteLine(logEntry);

            if (!Directory.Exists(_logsFolder))
                Directory.CreateDirectory(_logsFolder);

            lock (_logLock)
            {
                File.AppendAllText(_logFile, logEntry + Environment.NewLine);
            }
        }
    }
}