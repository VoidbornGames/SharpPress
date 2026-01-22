using MimeKit;
using Newtonsoft.Json;
using System.Text;
using SharpPress.Plugins;
using SharpPress.Services;

namespace SharpPress.Services
{
    public class PackageManager
    {
        private Logger _logger;
        private PluginManager _pluginManager;
        private string _pluginsFolder = Path.Combine(AppContext.BaseDirectory, "plugins");

        public PackageManager(Logger logger, PluginManager pluginManager)
        {
            _logger = logger;
            _pluginManager = pluginManager;
        }


        public async Task<bool> InstallPackage(Package package)
        {
            try
            {
                var pluginExist = _pluginManager.GetLoadedPlugins().FirstOrDefault(p => p.Key == package.Name, new KeyValuePair<string, IPlugin>("", null));
                if (pluginExist.Value == null)
                {
                    if (package == null || package.PluginDllData == null || package.Name == null) return false;

                    if (package.FileDataList.Any())
                    {
                        var plguinFolder = Path.Combine(_pluginsFolder, package.Name);
                        Directory.CreateDirectory(plguinFolder);
                        foreach (var fileData in package.FileDataList)
                            await File.WriteAllBytesAsync(Path.Combine(plguinFolder, fileData.Key), fileData.Value);
                    }
                    await File.WriteAllBytesAsync(Path.Combine(_pluginsFolder, $"{package.Name}.dll"), package.PluginDllData);

                    var tempDir = Path.Combine(Path.GetFullPath(_pluginsFolder), ".plugin_temp");
                    await _pluginManager.LoadPluginFromFileAsync(Path.Combine(_pluginsFolder, $"{package.Name}.dll"), tempDir);

                    return true;
                }
                else
                {
                    if (package == null || package.PluginDllData == null || package.Name == null) return false;

                    if (package.FileDataList.Any())
                    {
                        var plguinFolder = Path.Combine(_pluginsFolder, package.Name);
                        Directory.CreateDirectory(plguinFolder);
                        foreach (var fileData in package.FileDataList)
                            await File.WriteAllBytesAsync(Path.Combine(plguinFolder, fileData.Key), fileData.Value);
                    }

                    var tempFilePath = Path.Combine(_pluginsFolder, $"{package.Name}.tmp");
                    var finalFilePath = Path.Combine(_pluginsFolder, $"{package.Name}.dll");
                    await File.WriteAllBytesAsync(tempFilePath, package.PluginDllData);
                    await _pluginManager.UnloadAllPluginsAsync();

                    if (File.Exists(finalFilePath))
                    {
                        File.Delete(finalFilePath);
                    }
                    File.Move(tempFilePath, finalFilePath);
                    tempFilePath = null;

                    await _pluginManager.ReloadAllPluginsAsync();

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }
        }

        public async Task<Package> GetPackageFromByteArray(byte[] data)
        {
            try
            {
                var json = Encoding.UTF8.GetString(data);
                if (string.IsNullOrWhiteSpace(json)) return null;

                var package = JsonConvert.DeserializeObject<Package>(json);
                if (package == null || package.PluginDllData == null || package.Name == null) return null;

                return package;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return null;
            }
        }
    }

    public class Package
    {
        public string Name = "";
        public byte[] PluginDllData = [];
        public Dictionary<string, byte[]> FileDataList = new Dictionary<string, byte[]>();
    }
}
