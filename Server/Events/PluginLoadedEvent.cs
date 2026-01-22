using SharpPress.Models;
using SharpPress.Plugins;

namespace SharpPress.Events
{
    /// <summary>
    /// Event published when a new plugin successfully loads.
    /// </summary>
    public class PluginLoadedEvent : BaseEvent
    {
        public IPlugin Plugin { get; }

        public PluginLoadedEvent(IPlugin plugin)
        {
            Plugin = plugin;
        }
    }
}