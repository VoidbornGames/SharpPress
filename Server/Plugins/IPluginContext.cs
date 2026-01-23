using SharpPress.Services;

namespace SharpPress.Plugins
{
    /// <summary>
    /// Provides a secure API for plugins to interact with the core application.
    /// </summary>
    public interface IPluginContext
    {
        Logger Logger { get; }

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

        // --- Security & Service Access ---

        /// <summary>
        /// Securely retrieves a service from the Dependency Injection container.
        /// Throws an exception if the plugin does not have the required permission.
        /// </summary>
        /// <typeparam name="T">The type of service to retrieve.</typeparam>
        T GetService<T>();
    }
}