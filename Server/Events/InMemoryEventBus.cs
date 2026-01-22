using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace SharpPress.Services
{
    /// <summary>
    /// An in-memory implementation of an event bus.
    /// NOTE: This is not durable across server restarts and does not work in a multi-server environment.
    /// </summary>
    public class InMemoryEventBus : IEventBus
    {
        private readonly ConcurrentDictionary<Type, List<object>> _handlers = new();
        private readonly Logger _logger;

        public InMemoryEventBus(Logger logger)
        {
            _logger = logger;
        }

        public void Subscribe<T>(IEventHandler<T> handler) where T : IEvent
        {
            var eventType = typeof(T);
            var handlers = _handlers.GetOrAdd(eventType, _ => new List<object>());
            lock (handlers)
            {
                if (!handlers.Contains(handler))
                {
                    handlers.Add(handler);
                    _logger.Log($"👂 EventBus: Handler subscribed to event '{eventType.Name}'.");
                }
            }
        }

        public async Task PublishAsync<T>(T eventData) where T : IEvent
        {
            if (eventData == null) return;

            var eventType = typeof(T);
            if (!_handlers.TryGetValue(eventType, out var handlers))
            {
                _logger.Log($"📤 EventBus: No handlers registered for event '{eventType.Name}'.");
                return;
            }

            _logger.Log($"📤 EventBus: Publishing event '{eventType.Name}' (ID: {eventData.Id}).");

            List<IEventHandler<T>> typedHandlers;
            lock (handlers)
            {
                typedHandlers = handlers.Cast<IEventHandler<T>>().ToList();
            }

            var handlerTasks = typedHandlers.Select(async handler =>
            {
                try
                {
                    await handler.HandleAsync(eventData);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"❌ EventBus: Handler for event '{eventType.Name}' failed: {ex.Message}");
                }
            });

            await Task.WhenAll(handlerTasks);
        }
    }
}