using SharpPress.Services;
using System.Reflection;

namespace SharpPress.Plugins
{
    /// <summary>
    /// Provides a secure API for plugins to interact with the core application.
    /// </summary>
    public interface IPluginContext
    {
        Logger Logger { get; }

        /// <summary>
        /// Service provider to get access to core services.
        /// </summary>
        IServiceProvider ServiceProvider { get; }

        /// <summary>
        /// Factory to create scopes for Scoped services (used internally by GetService).
        /// </summary>
        IServiceScopeFactory ScopeFactory { get; }

        /// <summary>
        /// Adds an button to the admin sidebar menu.
        /// </summary>
        void RegisterAdminMenuItem(string name, string iconSvg, string url, int order = 0);

        /// <summary>
        /// Maps a GET route. 
        /// </summary>
        void MapGet(string pattern, Delegate handler);

        /// <summary>
        /// Maps a POST route.
        /// </summary>
        void MapPost(string pattern, Delegate handler);

        /// <summary>
        /// Maps a generic route (PUT, DELETE, etc).
        /// </summary>
        void Map(string pattern, Delegate handler);
    }
}