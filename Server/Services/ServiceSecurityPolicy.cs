using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SharpPress.Plugins;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;

namespace SharpPress.Services
{
    public class PluginSecurityOptions
    {
        public string DefaultMode { get; set; } = "Deny";
        public PluginPolicyEntry[] Policies { get; set; } = Array.Empty<PluginPolicyEntry>();
    }

    public class PluginPolicyEntry
    {
        public string ServiceType { get; set; } = "";
        public int RequiredPermission { get; set; }
    }

    public class ServiceSecurityPolicy
    {
        private readonly bool _defaultIsAllowed;
        private readonly ConcurrentDictionary<Type, PluginPermissions> _permissionCache = new();

        public ServiceSecurityPolicy(IConfiguration config, ILogger<ServiceSecurityPolicy> logger)
        {
            var options = config.GetSection("PluginSecurity").Get<PluginSecurityOptions>() ?? new PluginSecurityOptions();
            _defaultIsAllowed = options.DefaultMode.Equals("Allow", StringComparison.OrdinalIgnoreCase);

            foreach (var entry in options.Policies)
            {
                var type = Type.GetType(entry.ServiceType);
                if (type != null)
                {
                    _permissionCache[type] = (PluginPermissions)entry.RequiredPermission;
                }
                else
                {
                    type = AppDomain.CurrentDomain.GetAssemblies()
                        .SelectMany(a => a.GetTypes())
                        .FirstOrDefault(t => t.FullName == entry.ServiceType || t.Name == entry.ServiceType);
                    if (type != null)
                        _permissionCache[type] = (PluginPermissions)entry.RequiredPermission;
                }
            }
        }

        public bool HasAccess(Type serviceType, PluginPermissions grantedPermissions)
        {
            if (_permissionCache.TryGetValue(serviceType, out var required))
            {
                return grantedPermissions.HasFlag(required);
            }
            return _defaultIsAllowed;
        }
    }
}