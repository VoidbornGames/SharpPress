using Microsoft.AspNetCore.Routing;
using System;
using System.Threading.Tasks;

namespace SharpPress.Plugins
{
    /// <summary>
    /// The main contract that all plugins must implement.
    /// </summary>
    public interface IPlugin
    {
        string Name { get; }
        string Version { get; }

        /// <summary>
        /// Called when the plugin is loaded.
        /// </summary>
        Task OnLoadAsync(IPluginContext context);
        Task OnUpdateAsync(IPluginContext context);
        Task OnUnloadAsync();
    }
}