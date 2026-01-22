namespace SharpPress.Events
{
    /// <summary>
    /// Event published when a video is successfully uploaded.
    /// </summary>
    public class VideoUploadedEvent : BaseEvent
    {
        public string FileName { get; }
        public string SourceUrl { get; }

        public VideoUploadedEvent(string fileName, string sourceUrl)
        {
            FileName = fileName;
            SourceUrl = sourceUrl;
        }
    }
}