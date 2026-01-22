using System;
using SharpPress.Events;
using SharpPress.Models;

namespace SharpPress.Services
{
    public class VideoService
    {
        private readonly string _videosFolder;
        private readonly Logger _logger;
        private readonly IEventBus _eventBus;

        public VideoService(
            FilePaths filePaths,
            Logger logger,
            IEventBus eventBus)
        {
            _videosFolder = filePaths.VideosFolder;
            _logger = logger;
            _eventBus = eventBus;
            PrepareVideos();
        }

        private void PrepareVideos()
        {
            try
            {
                if (!Directory.Exists(_videosFolder)) Directory.CreateDirectory(_videosFolder);
                _logger.Log("✅ Videos folder ready.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error preparing videos folder: {ex.Message}");
            }
        }

        public string[] GetVideoFiles()
        {
            try
            {
                string videoDir = Path.Combine(AppContext.BaseDirectory, _videosFolder);
                Directory.CreateDirectory(videoDir);

                string[] files = Directory.GetFiles(videoDir)
                    .Where(f => IsVideoFile(f))
                    .Select(f => Path.GetFileName(f))
                    .ToArray();

                //_logger.Log($"✅ Found {files.Length} video files");
                return files;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting video files: {ex.Message}");
                return Array.Empty<string>();
            }
        }

        public async Task<(bool success, string message)> DownloadVideoFromUrl(string videoUrl)
        {
            if (string.IsNullOrWhiteSpace(videoUrl))
            {
                return (false, "URL cannot be empty");
            }

            string videoDir = Path.Combine(AppContext.BaseDirectory, _videosFolder);
            Directory.CreateDirectory(videoDir);

            string fileName = Path.GetFileName(new Uri(videoUrl).LocalPath);
            if (string.IsNullOrEmpty(fileName) || !fileName.Contains('.'))
            {
                fileName = "downloaded_" + DateTime.Now.Ticks + ".mp4";
            }

            fileName = string.Join("_", fileName.Split(Path.GetInvalidFileNameChars()));
            string filePath = Path.Combine(videoDir, fileName);

            _logger.Log($"📥 Starting download from: {videoUrl}");

            using var httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromMinutes(10);

            try
            {
                using var responseMessage = await httpClient.GetAsync(videoUrl, HttpCompletionOption.ResponseHeadersRead);

                if (!responseMessage.IsSuccessStatusCode)
                {
                    _logger.LogError($"Download failed with status: {responseMessage.StatusCode}");
                    return (false, $"Download failed: HTTP {responseMessage.StatusCode}");
                }

                string contentType = responseMessage.Content.Headers.ContentType?.MediaType ?? "";
                if (!contentType.StartsWith("video/") && !contentType.Contains("octet-stream"))
                {
                    _logger.Log($"⚠️ Warning: Content type is {contentType}, but proceeding anyway");
                }

                using var responseStream = await responseMessage.Content.ReadAsStreamAsync();
                using var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write);

                long totalBytes = responseMessage.Content.Headers.ContentLength ?? 0;
                long downloadedBytes = 0;
                byte[] buffer = new byte[8192];
                int bytesRead;

                while ((bytesRead = await responseStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await fileStream.WriteAsync(buffer, 0, bytesRead);
                    downloadedBytes += bytesRead;

                    if (totalBytes > 0 && downloadedBytes % (1024 * 1024) == 0)
                    {
                        double progress = (double)downloadedBytes / totalBytes * 100;
                        _logger.Log($"📥 Download progress: {progress:F1}%");
                    }
                }

                await fileStream.FlushAsync();

                if (new FileInfo(filePath).Length > 0)
                {
                    _logger.Log($"✅ Video downloaded successfully: {fileName} ({new FileInfo(filePath).Length} bytes)");

                    await _eventBus.PublishAsync(new VideoUploadedEvent(fileName, videoUrl));

                    return (true, $"Download successful: {fileName}");
                }
                else
                {
                    File.Delete(filePath);
                    _logger.LogError("Downloaded file is empty");
                    return (false, "Downloaded file is empty");
                }
            }
            catch (TaskCanceledException)
            {
                _logger.LogError("Download timed out");
                return (false, "Download timed out");
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError($"HTTP error during download: {httpEx.Message}");
                return (false, $"Download failed: {httpEx.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"URL Download failed: {ex.Message}");
                return (false, $"Download failed: {ex.Message}");
            }
        }


        public bool IsVideoFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return false;

            string extension = Path.GetExtension(filePath).ToLowerInvariant();
            return extension == ".mp4" || extension == ".webm" || extension == ".ogg" ||
                   extension == ".avi" || extension == ".mov" || extension == ".mkv";
        }

        public string GetVideoFilePath(string fileName)
        {
            if (fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
            {
                _logger.Log($"❌ Invalid filename requested: {fileName}");
                return null;
            }

            string filePath = Path.Combine(AppContext.BaseDirectory, _videosFolder, fileName);
            return File.Exists(filePath) ? filePath : null;
        }

        public string GetContentType(string filePath)
        {
            string extension = Path.GetExtension(filePath).ToLowerInvariant();
            return extension switch
            {
                ".mp4" => "video/mp4",
                ".webm" => "video/webm",
                ".ogg" => "video/ogg",
                ".avi" => "video/x-msvideo",
                ".mov" => "video/quicktime",
                ".mkv" => "video/x-matroska",
                _ => "application/octet-stream"
            };
        }
    }
}