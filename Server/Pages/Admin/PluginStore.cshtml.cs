using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SharpPress.Services;
using System.Text.Json;

namespace SharpPress.Pages
{
    public class PluginStoreModel : PageModel
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly PluginManager pluginManager;

        private const string PluginsJsonUrl = "https://github.com/VoidbornGames/SharpPress_Plugins/raw/refs/heads/main/plugins.json";

        public List<PluginInfo> Plugins { get; set; } = new();
        public string ErrorMessage { get; set; }

        public PluginStoreModel(IHttpClientFactory httpClientFactory, PluginManager _pluginManager)
        {
            _httpClientFactory = httpClientFactory;
            pluginManager = _pluginManager;
        }

        public async Task OnGetAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient();
                var json = await client.GetStringAsync(PluginsJsonUrl);
                var manifest = JsonSerializer.Deserialize<PluginsManifest>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                Plugins = manifest?.Plugins ?? new();
            }
            catch
            {
                ErrorMessage = "Failed to load plugins. Please try again later.";
            }
        }

        public async Task<IActionResult> OnPostInstallAsync(string id)
        {
            var client = _httpClientFactory.CreateClient();
            try
            {
                var json = await client.GetStringAsync(PluginsJsonUrl);
                var manifest = JsonSerializer.Deserialize<PluginsManifest>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                Plugins = manifest?.Plugins ?? new();
            }
            catch
            {
                ErrorMessage = "Failed to load plugins. Please try again later.";
                return Page();
            }

            var plugin = Plugins.FirstOrDefault(p => p.Id == id);
            if (plugin == null)
            {
                ErrorMessage = "Plugin not found.";
                return Page();
            }

            var fileName = Path.GetFileName(plugin.DownloadUrl);
            var filePath = Path.Combine("plugins", fileName);

            var existingKey = pluginManager.PluginToAssemblyPath.FirstOrDefault(p => p.Value == filePath).Key;

            if (System.IO.File.Exists(filePath) && !string.IsNullOrWhiteSpace(existingKey))
            {
                await pluginManager.UnloadPluginAsync(existingKey);
                System.IO.File.Delete(filePath);
            }

            try
            {
                var pluginBytes = await client.GetByteArrayAsync(plugin.DownloadUrl);
                await System.IO.File.WriteAllBytesAsync(filePath, pluginBytes);
            }
            catch
            {
                ErrorMessage = "Failed to download plugin.";
                return Page();
            }

            await pluginManager.LoadPluginFromFileAsync(filePath);
            return RedirectToPage("/Admin/Plugins");
        }

        public class PluginsManifest
        {
            public List<PluginInfo> Plugins { get; set; }
        }

        public class PluginInfo
        {
            public string Id { get; set; }
            public string Name { get; set; }
            public string Version { get; set; }
            public string Author { get; set; }
            public string Description { get; set; }
            public string Icon { get; set; }
            public string DownloadUrl { get; set; }
            public string MinVersion { get; set; }
        }
    }
}