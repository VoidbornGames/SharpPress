using Microsoft.AspNetCore.Mvc.ApplicationModels;
using SharpPress.Services;

namespace SharpPress.Plugins
{
    public class PluginPageConvention : IPageConvention
    {
        public void Apply(PageApplicationModel model)
        {
            // Filters are applied through the IAsyncPageFilter in PluginEnabledFilter
            // This convention is just a placeholder to satisfy the API
        }
    }
}