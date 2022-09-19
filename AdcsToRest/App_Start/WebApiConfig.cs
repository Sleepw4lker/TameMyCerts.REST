using System.Net.Http.Headers;
using System.Web.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

namespace AdcsToRest
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.MapHttpAttributeRoutes();

            config.Formatters.Remove(config.Formatters.XmlFormatter);

            var jsonFormatter = GlobalConfiguration.Configuration.Formatters.JsonFormatter;

            jsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            jsonFormatter.SerializerSettings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy(),
                false));
            jsonFormatter.SerializerSettings.Formatting = Formatting.Indented;
            jsonFormatter.SupportedMediaTypes.Clear();
            jsonFormatter.SupportedMediaTypes.Add(new MediaTypeHeaderValue("application/json"));

            config.Formatters.Add(jsonFormatter);
        }
    }
}