using SharpPress.Models;

namespace SharpPress.Events
{
    /// <summary>
    /// Event published when a new user successfully registers.
    /// </summary>
    public class UserRegisteredEvent : BaseEvent
    {
        public User User { get; }

        public UserRegisteredEvent(User user)
        {
            User = user;
        }
    }
}