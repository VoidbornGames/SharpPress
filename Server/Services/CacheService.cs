using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress.Services
{
    public class CacheService
    {
        private readonly ConcurrentDictionary<string, CacheItem> _cache = new();
        private readonly ServerConfig _config;
        private readonly Logger _logger;

        public CacheService(ServerConfig config, Logger logger)
        {
            _config = config;
            _logger = logger;

            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5));
                    CleanupExpiredItems();
                }
            });
        }

        public T Get<T>(string key)
        {
            if (_cache.TryGetValue(key, out var item))
            {
                if (item.Expiry > DateTime.UtcNow)
                {
                    return (T)item.Value;
                }
                else
                {
                    _cache.TryRemove(key, out _);
                }
            }
            return default;
        }

        public void Set<T>(string key, T value, TimeSpan? expiry = null)
        {
            var expiration = expiry ?? TimeSpan.FromMinutes(_config.CacheExpiryMinutes);
            _cache.AddOrUpdate(key,
                new CacheItem { Value = value, Expiry = DateTime.UtcNow.Add(expiration) },
                (k, v) => new CacheItem { Value = value, Expiry = DateTime.UtcNow.Add(expiration) });
        }

        public bool Remove(string key)
        {
            return _cache.TryRemove(key, out _);
        }

        public bool Exists(string key)
        {
            if (_cache.TryGetValue(key, out var item))
            {
                if (item.Expiry > DateTime.UtcNow)
                {
                    return true;
                }
                else
                {
                    _cache.TryRemove(key, out _);
                }
            }
            return false;
        }

        private void CleanupExpiredItems()
        {
            var now = DateTime.UtcNow;
            var keysToRemove = new List<string>();

            foreach (var kvp in _cache)
            {
                if (kvp.Value.Expiry <= now)
                {
                    keysToRemove.Add(kvp.Key);
                }
            }

            foreach (var key in keysToRemove)
            {
                _cache.TryRemove(key, out _);
            }

            if (keysToRemove.Count > 0)
            {
                _logger.Log($"🧹 Cache cleanup: removed {keysToRemove.Count} expired items");
            }
        }

        private class CacheItem
        {
            public object Value { get; set; }
            public DateTime Expiry { get; set; }
        }
    }
}