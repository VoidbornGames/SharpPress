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

        public async Task<IActionResult> OnPostUpload(IFormFile pluginFile)
        {
            if (pluginFile != null && pluginFile.FileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                var filePath = Path.Combine("plugins", pluginFile.FileName);
                var pluginName = pluginManager.PluginToAssemblyPath.Where(p => p.Value == filePath).FirstOrDefault().Key;

                if (System.IO.File.Exists(filePath) && !string.IsNullOrWhiteSpace(pluginName))
                {
                    await pluginManager.UnloadPluginAsync(pluginName);
                    System.IO.File.Delete(filePath);
                }

                using var stream = new FileStream(filePath, FileMode.Create);
                await pluginFile.CopyToAsync(stream);

                await pluginManager.LoadPluginFromFileAsync(filePath);
            }

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
