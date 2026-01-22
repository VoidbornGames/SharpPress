using System;
using System.Net;
using UltimateServer.Plugins;
using UltimateServer.Services;

namespace TestPlugin
{
    public class TestPlugin : IPlugin
    {
        public string Name => "TestPlugin";
        public string Version => "2.1.155";


        public Task OnLoadAsync(IPluginContext context)
        {
            return Task.CompletedTask;
        }

        public Task OnUpdateAsync(IPluginContext context)
        {
            return Task.CompletedTask;
        }

        public Task OnUnloadAsync()
        {
            return Task.CompletedTask;
        }
    }
}
