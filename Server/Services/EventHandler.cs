using System.Threading.Tasks;
using SharpPress.Events;

namespace SharpPress.Services
{
    /// <summary>
    /// Service responsible to handle notifications, reacting to various domain events.
    /// </summary>
    public class EventHandler : 
        IEventHandler<UserRegisteredEvent>,
        IEventHandler<VideoUploadedEvent>,
        IEventHandler<PluginLoadedEvent>
    {
        private readonly Logger _logger;

        public EventHandler(Logger logger)
        {
            _logger = logger;
        }

        public async Task HandleAsync(UserRegisteredEvent eventData)
        {
            await Task.Run(() =>
            {
                _logger.Log($"🎉 Notification: New user '{eventData.User.Username}' (Email: {eventData.User.Email}) has registered! Welcome them.");
            });
        }

        public async Task HandleAsync(VideoUploadedEvent eventData)
        {
            await Task.Run(() =>
            {
                _logger.Log($"🎬 Notification: Video '{eventData.FileName}' from URL '{eventData.SourceUrl}' has been uploaded and is ready for processing.");
            });
        }

        public async Task HandleAsync(PluginLoadedEvent eventData)
        {

        }
    }
}