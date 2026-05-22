using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress.Pages
{
    public class PluginsModel : PageModel
    {
        private readonly UserService userService;
        private readonly PluginManager pluginManager;

        public PluginsModel(UserService _userService, PluginManager _pluginManager)
        {
            userService = _userService;
            pluginManager = _pluginManager;
        }

        public async Task<IActionResult> OnGet()
        {
            var user = await userService.GetUserAsync(User);
            if (user == null || !user.HasRole(UserRole.Admin))
                return RedirectToPage("/Login");

            return Page();
        }

        public async Task<IActionResult> OnPostEnableAsync(string name)
        {
            if (await pluginManager.EnablePluginAsync(name))
                return Page();
            else
                return StatusCode(500, "Server error! please try again.");
        }

        public async Task<IActionResult> OnPostDisableAsync(string name)
        {
            if (await pluginManager.DisablePluginAsync(name))
                return Page();
            else
                return StatusCode(500, "Server error! please try again.");
        }
    }
}
