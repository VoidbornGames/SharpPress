using System;
using System.Threading.Tasks;

namespace SharpPress.Services
{
    /// <summary>
    /// Marker interface for all domain events.
    /// </summary>
    public interface IEvent
    {
        Guid Id { get; }
        DateTime Timestamp { get; }
    }

    /// <summary>
    /// Defines a handler for a specific type of event.
    /// </summary>
    /// <typeparam name="T">The type of event this handler can process.</typeparam>
    public interface IEventHandler<in T> where T : IEvent
    {
        /// <summary>
        /// Handles the provided event asynchronously.
        /// </summary>
        /// <param name="eventData">The event data.</param>
        Task HandleAsync(T eventData);
    }

    /// <summary>
    /// Defines the contract for an event bus, responsible for publishing and subscribing to events.
    /// </summary>
    public interface IEventBus
    {
        /// <summary>
        /// Publishes an event to all registered subscribers asynchronously.
        /// </summary>
        /// <typeparam name="T">The type of event to publish.</typeparam>
        /// <param name="eventData">The event data to publish.</param>
        Task PublishAsync<T>(T eventData) where T : IEvent;

        /// <summary>
        /// Subscribes a handler to a specific type of event.
        /// </summary>
        /// <typeparam name="T">The type of event to subscribe to.</typeparam>
        /// <param name="handler">The handler that will process the event.</param>
        void Subscribe<T>(IEventHandler<T> handler) where T : IEvent;
    }
}