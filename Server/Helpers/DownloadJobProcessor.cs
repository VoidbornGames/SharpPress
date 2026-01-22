using SharpPress.Models;
using SharpPress.Servers;
using SharpPress.Services;
using System.Collections.Concurrent;

namespace SharpPress.Helpers
{
    public class DownloadJobProcessor
    {
        private readonly ConcurrentQueue<MarketPlugin> _jobQueue = new ConcurrentQueue<MarketPlugin>();
        private readonly SemaphoreSlim _signal = new SemaphoreSlim(0);
        private readonly Logger _logger;
        private readonly PluginManager _pluginManager;
        private readonly PackageManager _packageManager;
        private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private Task _processingTask;

        public DownloadJobProcessor(Logger logger, PluginManager pluginManager, PackageManager packageManager)
        {
            _logger = logger;
            _pluginManager = pluginManager;
            _packageManager = packageManager;
            _processingTask = Task.Run(ProcessJobsAsync);
        }

        public void EnqueueJob(MarketPlugin downloadRequest)
        {
            if (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                _jobQueue.Enqueue(downloadRequest);
                _signal.Release();
            }
        }

        private async Task ProcessJobsAsync()
        {
            try
            {
                while (true)
                {
                    await _signal.WaitAsync(_cancellationTokenSource.Token);

                    if (_cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        break;
                    }

                    if (_jobQueue.TryDequeue(out var downloadRequest))
                    {
                        try
                        {
                            await ProcessDownloadJobAsync(downloadRequest);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error processing market download job: {ex.Message}");
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
        }

        private async Task ProcessDownloadJobAsync(MarketPlugin downloadRequest)
        {
            if (downloadRequest.isPackaged == false)
            {
                string pluginsDirectory = Path.Combine(AppContext.BaseDirectory, "plugins");
                string fileName = $"{downloadRequest.Name}.dll";
                string filePath = Path.Combine(pluginsDirectory, fileName);

                Directory.CreateDirectory(pluginsDirectory);

                using var client = new HttpClient();
                var downloadResponse = await client.GetAsync(downloadRequest.DownloadLink, HttpCompletionOption.ResponseHeadersRead, _cancellationTokenSource.Token);

                if (!downloadResponse.IsSuccessStatusCode)
                {
                    _logger.LogError($"Failed to download file from URL: {downloadRequest.DownloadLink}. Status: {downloadResponse.StatusCode}");
                    return;
                }

                using (var contentStream = await downloadResponse.Content.ReadAsStreamAsync())
                using (var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await contentStream.CopyToAsync(fileStream, _cancellationTokenSource.Token);
                }

                _logger.Log($"Successfully downloaded and saved plugin to: {filePath}");
                await _pluginManager.ReloadAllPluginsAsync();
            }
            else
            {
                string pluginsDirectory = Path.Combine(AppContext.BaseDirectory, "plugins");
                Directory.CreateDirectory(pluginsDirectory);

                using var client = new HttpClient();
                var downloadResponse = await client.GetAsync(downloadRequest.DownloadLink, HttpCompletionOption.ResponseHeadersRead, _cancellationTokenSource.Token);

                if (!downloadResponse.IsSuccessStatusCode)
                {
                    _logger.LogError($"Failed to download file from URL: {downloadRequest.DownloadLink}. Status: {downloadResponse.StatusCode}");
                    return;
                }

                var content = await downloadResponse.Content.ReadAsByteArrayAsync();
                var package = await _packageManager.GetPackageFromByteArray(content);

                if (package != null)
                    await _packageManager.InstallPackage(package);
                else
                    _logger.LogError($"Can't Install Packaged Plugin: '{downloadRequest.Name}' From '{downloadRequest.DownloadLink}'");
            }
        }

        public async Task StopAsync()
        {
            _cancellationTokenSource.Cancel();
            await _processingTask;
        }
    }
}
