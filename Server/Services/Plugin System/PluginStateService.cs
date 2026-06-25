using System.Text.Json;

namespace SharpPress.Services
{
    public class PluginStateService
    {
        private readonly string _statePath;
        private Dictionary<string, bool> _state = new();

        public PluginStateService(string statePath = "plugins/plugin-state.json")
        {
            _statePath = statePath;
            Load();
        }

        public bool IsEnabled(string pluginName)
        {
            return !_state.TryGetValue(pluginName, out var enabled) || enabled;
        }

        public void SetEnabled(string pluginName, bool enabled)
        {
            _state[pluginName] = enabled;
            Save();
        }

        public void Remove(string pluginName)
        {
            _state.Remove(pluginName);
            Save();
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_statePath)) return;
                var json = File.ReadAllText(_statePath);
                var deserializedState = JsonSerializer.Deserialize<Dictionary<string, bool>>(json);

                if (deserializedState is null)
                {
                    Console.Error.WriteLine($"Plugin state file '{_statePath}' was deserialized as null. Falling back to empty plugin state.");
                    _state = new();
                }
                else
                    _state = deserializedState;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to load plugin state from '{_statePath}': {ex}");
                _state = new();
            }
        }

        private void Save()
        {
            try
            {
                var directory = Path.GetDirectoryName(_statePath);
                if (!string.IsNullOrEmpty(directory))
                    Directory.CreateDirectory(directory);

                var json = JsonSerializer.Serialize(_state, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_statePath, json);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to save plugin state to '{_statePath}': {ex}");
            }
        }
    }
}