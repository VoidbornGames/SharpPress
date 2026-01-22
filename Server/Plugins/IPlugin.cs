using System.Threading.Tasks;

namespace SharpPress.Plugins
{
    /// <summary>
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
        /// The version of the plugin.
        /// </summary>
        string Version { get; }

        /// <summary>
        /// This method is called by the Plugin Manager when the plugin is loaded.
        /// </summary>
        /// <param name="context">A context providing access to core services.</param>
        Task OnLoadAsync(IPluginContext context);

        /// <summary>
        /// This method is called by the Plugin Manager 1 time per second.
        /// </summary>
        /// <param name="context">A context providing access to core services.</param>
        Task OnUpdateAsync(IPluginContext context);

        /// <summary>
        /// This method is called by the Plugin Manager when the plugin is unloaded.
        /// </summary>
        Task OnUnloadAsync();
    }
}