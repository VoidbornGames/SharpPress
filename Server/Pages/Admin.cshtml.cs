using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SharpPress.Models;
using SharpPress.Services;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;

namespace SharpPress.Pages
{
    public class AdminModel : PageModel
    {
        private readonly UserService _userService;
        private readonly PluginManager _pluginManager;
        private readonly FeatherDatabase database;

        public AdminModel(UserService userService, PluginManager pluginManager, FeatherDatabase _database)
        {
            _userService = userService;
            _pluginManager = pluginManager;
            database = _database;
        }

        public string Uptime { get; set; }
        public string CpuUsage { get; set; }
        public string MemoryMB { get; set; }
        public long Users { get; set; }
        public string DiskUsedGB { get; set; }
        public string DiskTotalGB { get; set; }
        public string NetReceivedMB { get; set; }
        public string NetSentMB { get; set; }
        public int ActivePlugins { get; set; }

        public async Task<IActionResult> OnGet()
        {
            var user = await _userService.GetUserAsync(User);
            if (user == null || !user.HasRole(UserRole.Admin))
                return RedirectToPage("/Login");

            var process = Process.GetCurrentProcess();
            var elapsed = DateTime.Now - process.StartTime;

            Uptime = $"{elapsed.Days:D2}:{elapsed.Hours:D2}:{elapsed.Minutes:D2}:{elapsed.Seconds:D2}";
            MemoryMB = (process.WorkingSet64 / 1024.0 / 1024.0).ToString("F2");

            var totalMs = Environment.ProcessorCount * elapsed.TotalMilliseconds;
            var cpuPercent = totalMs > 0 ? (process.TotalProcessorTime.TotalMilliseconds / totalMs) * 100 : 0;
            CpuUsage = cpuPercent.ToString("F1");

            Users = await database.Count<User>();
            ActivePlugins = _pluginManager.GetLoadedPlugins().Count;

            try
            {
                var root = Path.GetPathRoot(AppContext.BaseDirectory);
                var drive = new DriveInfo(root);
                DiskUsedGB = ((drive.TotalSize - drive.AvailableFreeSpace) / 1024.0 / 1024.0 / 1024.0).ToString("F2");
                DiskTotalGB = (drive.TotalSize / 1024.0 / 1024.0 / 1024.0).ToString("F2");
            }
            catch
            {
                DiskUsedGB = "N/A";
                DiskTotalGB = "N/A";
            }

            try
            {
                long totalReceived = 0;
                long totalSent = 0;
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up
                             && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

                foreach (var nic in interfaces)
                {
                    var stats = nic.GetIPv4Statistics();
                    totalReceived += stats.BytesReceived;
                    totalSent += stats.BytesSent;
                }

                NetReceivedMB = (totalReceived / 1024.0 / 1024.0).ToString("F2");
                NetSentMB = (totalSent / 1024.0 / 1024.0).ToString("F2");
            }
            catch
            {
                NetReceivedMB = "N/A";
                NetSentMB = "N/A";
            }

            return Page();
        }
    }
}