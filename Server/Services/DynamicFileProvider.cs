using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using System.Collections;

namespace SharpPress.Services
{
    /// <summary>
    /// A composite file provider that wraps the main app's file system 
    /// and adds file systems from plugins.
    /// </summary>
    public class DynamicFileProvider : IFileProvider
    {
        private readonly List<IFileProvider> _providers = new();
        private readonly object _lock = new object();


        public DynamicFileProvider(IFileProvider defaultProvider)
        {
            _providers.Add(defaultProvider);
        }

        public void AddProvider(IFileProvider provider)
        {
            lock (_lock)
            {
                if (!_providers.Contains(provider))
                {
                    _providers.Add(provider);
                }
            }
        }

        /// <summary>
        /// Removes all added plugin providers, keeping only the default.
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                if (_providers.Count > 1)
                {
                    _providers.RemoveRange(1, _providers.Count - 1);
                }
            }
        }

        public IDirectoryContents GetDirectoryContents(string subpath)
        {
            var contents = new CompositeDirectoryContents();
            lock (_lock)
            {
                foreach (var provider in _providers)
                {
                    var dirContents = provider.GetDirectoryContents(subpath);
                    if (dirContents.Exists)
                    {
                        contents.Add(dirContents);
                    }
                }
            }
            return contents;
        }

        public IFileInfo GetFileInfo(string subpath)
        {
            lock (_lock)
            {
                for (int i = _providers.Count - 1; i >= 0; i--)
                {
                    var info = _providers[i].GetFileInfo(subpath);
                    if (info.Exists)
                        return info;
                }
            }
            return new NotFoundFileInfo(subpath);
        }

        public IChangeToken Watch(string filter)
        {
            return NullChangeToken.Singleton;
        }

        private class CompositeDirectoryContents : IDirectoryContents
        {
            private readonly List<IFileInfo> _files = new();

            public bool Exists => _files.Any();

            public void Add(IDirectoryContents contents)
            {
                foreach (var item in contents)
                {
                    _files.Add(item);
                }
            }

            public IEnumerator<IFileInfo> GetEnumerator() => _files.GetEnumerator();
            IEnumerator IEnumerable.GetEnumerator() => _files.GetEnumerator();
        }
    }
}