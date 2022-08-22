﻿using System.Web.Mvc;
using System.Web.Routing;

namespace AdcsToRest
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            routes.MapRoute(
                "Default",
                string.Empty,
                new {controller = "Home", action = "Index", id = UrlParameter.Optional}
            );
        }
    }
}