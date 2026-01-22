using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;
using SharpPress.Models;
using SharpPress.Services;

namespace SharpPress.Services
{
    public class CompressionService
    {
        private readonly ServerConfig _config;
        private readonly Logger _logger;

        public CompressionService(ServerConfig config, Logger logger)
        {
            _config = config;
            _logger = logger;
        }

        public async Task<byte[]> CompressAsync(byte[] data, string compressionType = "gzip")
        {
            if (!_config.EnableCompression || data == null || data.Length < 1024)
            {
                return data;
            }

            using var output = new MemoryStream();

            if (compressionType == "gzip")
            {
                using (var gzip = new GZipStream(output, CompressionMode.Compress))
                {
                    await gzip.WriteAsync(data, 0, data.Length);
                }
            }
            else if (compressionType == "deflate")
            {
                using (var deflate = new DeflateStream(output, CompressionMode.Compress))
                {
                    await deflate.WriteAsync(data, 0, data.Length);
                }
            }

            return output.ToArray();
        }

        public async Task<byte[]> DecompressAsync(byte[] data, string compressionType = "gzip")
        {
            if (data == null || data.Length == 0)
            {
                return data;
            }

            using var input = new MemoryStream(data);
            using var output = new MemoryStream();

            if (compressionType == "gzip")
            {
                using (var gzip = new GZipStream(input, CompressionMode.Decompress))
                {
                    await gzip.CopyToAsync(output);
                }
            }
            else if (compressionType == "deflate")
            {
                using (var deflate = new DeflateStream(input, CompressionMode.Decompress))
                {
                    await deflate.CopyToAsync(output);
                }
            }

            return output.ToArray();
        }

        public bool ShouldCompress(string contentType)
        {
            if (!_config.EnableCompression)
                return false;

            if (contentType.Contains("image/") ||
                contentType.Contains("video/") ||
                contentType.Contains("application/zip") ||
                contentType.Contains("application/gzip"))
            {
                return false;
            }

            return contentType.Contains("text/") ||
                   contentType.Contains("application/json") ||
                   contentType.Contains("application/xml") ||
                   contentType.Contains("application/javascript");
        }
    }
}