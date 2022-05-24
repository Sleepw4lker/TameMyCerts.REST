using System.Web.Http;
using Newtonsoft.Json.Serialization;

namespace AdcsToRest
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                "DefaultApi",
                "{controller}/{id}",
                new {id = RouteParameter.Optional}
            );

            #region this converts pascal-cased .NET objects to JSON camelcase

            config.Formatters.Remove(config.Formatters.XmlFormatter);

            var json = GlobalConfiguration.Configuration.Formatters.JsonFormatter;
            json.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();

            #endregion

        }
    }
}