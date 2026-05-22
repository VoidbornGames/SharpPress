using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress.Pages
{
    public class SettingsModel : PageModel
    {
        private readonly ConfigManager _configManager;
        private readonly UserService _userService;

        public SettingsModel(ConfigManager configManager, UserService userService)
        {
            _configManager = configManager;
            _userService = userService;
        }

        [BindProperty]
        public SettingsInput Input { get; set; } = new SettingsInput();

        public string ActiveTab { get; set; } = "general";

        public async Task<IActionResult> OnGet()
        {
            var user = await _userService.GetUserAsync(User);
            if (user == null || !user.HasRole(UserRole.Admin))
                return RedirectToPage("/Login");

            var s = _configManager.Config.SiteSettings;

            Input.SiteName = s?.General?.SiteName ?? "";
            Input.SiteDescription = s?.General?.SiteDescription ?? "";
            Input.AdminEmail = s?.General?.AdminEmail ?? "";
            Input.Timezone = s?.General?.Timezone ?? "UTC";
            Input.FooterText = s?.General?.FooterText ?? "";
            Input.ForceHttps = s?.Security?.ForceHttps ?? false;
            Input.AllowRegistration = s?.Security?.AllowRegistration ?? false;
            Input.Require2FA = s?.Security?.Require2FA ?? false;
            Input.SessionTimeout = s?.Security?.SessionTimeout ?? 60;
            Input.EnableCache = s?.Advanced?.EnableCache ?? true;
            Input.MaintenanceMode = s?.Advanced?.MaintenanceMode ?? false;
            Input.CustomCss = s?.Advanced?.CustomCss ?? "";

            return Page();
        }

        public async Task<IActionResult> OnPost(string activeTab = "general")
        {
            var user = await _userService.GetUserAsync(User);
            if (user == null || !user.HasRole(UserRole.Admin))
                return RedirectToPage("/Login");

            ActiveTab = activeTab;
            ModelState.Clear();

            _configManager.Config.SiteSettings = new SiteSettings
            {
                General = new GeneralSettings
                {
                    SiteName = Input.SiteName ?? "",
                    SiteDescription = Input.SiteDescription ?? "",
                    AdminEmail = Input.AdminEmail ?? "",
                    Timezone = Input.Timezone ?? "UTC",
                    FooterText = Input.FooterText ?? ""
                },
                Security = new SecuritySettings
                {
                    ForceHttps = Input.ForceHttps,
                    AllowRegistration = Input.AllowRegistration,
                    Require2FA = Input.Require2FA,
                    SessionTimeout = Input.SessionTimeout
                },
                Advanced = new AdvancedSettings
                {
                    EnableCache = Input.EnableCache,
                    MaintenanceMode = Input.MaintenanceMode,
                    CustomCss = Input.CustomCss ?? ""
                }
            };

            await _configManager.SaveConfig();
            TempData["SuccessMessage"] = "Settings updated successfully.";

            return RedirectToPage("/Settings", new { tab = activeTab });
        }

        public class SettingsInput
        {
            public string SiteName { get; set; }
            public string SiteDescription { get; set; }
            public string AdminEmail { get; set; }
            public string Timezone { get; set; }
            public string FooterText { get; set; }
            public bool ForceHttps { get; set; }
            public bool AllowRegistration { get; set; }
            public bool Require2FA { get; set; }
            public int SessionTimeout { get; set; }
            public bool EnableCache { get; set; }
            public bool MaintenanceMode { get; set; }
            public string CustomCss { get; set; }
        }
    }
}