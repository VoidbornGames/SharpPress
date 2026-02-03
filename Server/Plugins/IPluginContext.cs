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
        IServiceProvider ServiceProvider { get; }

        /// <summary>
        /// Factory to create scopes for Scoped services (used internally by GetService).
        /// </summary>
        IServiceScopeFactory ScopeFactory { get; }

        // --- Minimal API Integration ---

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