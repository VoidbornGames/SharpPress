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
        /// <summary>
        /// The name of the plugin.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// The version of pluign.
        /// </summary>
        string Version { get; }

        /// <summary>
        /// The author who made the plugin.
        /// </summary>
        string Author { get; }

        /// <summary>
        /// A short description of the plugin.
        /// </summary>
        string? Description { get; }

        /// <summary>
        /// Called when the plugin is loaded.
        /// </summary>
        Task OnLoadAsync(IPluginContext context);

        /// <summary>
        /// Called when the plugin recives a update event.
        /// </summary>
        Task OnUpdateAsync(IPluginContext context);

        /// <summary>
        /// Called when the plugin is unloading.
        /// </summary>
        Task OnUnloadAsync();
    }
}