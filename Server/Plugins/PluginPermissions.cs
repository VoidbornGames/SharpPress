using System;

namespace SharpPress.Plugins
{
    [Flags]
    public enum PluginPermissions
    {
        None = 0,
        // Ability to read/write to the database
        DatabaseAccess = 1 << 0,
        // Ability to make HTTP requests (HttpClient)
        NetworkAccess = 1 << 1,
        // Ability to read/write local server files
        FileSystemAccess = 1 << 2,
        // Ability to access the EventBus
        EventBusAccess = 1 << 3
    }
}