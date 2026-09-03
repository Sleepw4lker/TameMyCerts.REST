// Copyright (c) Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
var appName = Assembly.GetExecutingAssembly().GetName().Name;

builder.Logging.AddEventLog(settings =>
{
    settings.SourceName = appName;
});

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.JsonSerializerOptions.WriteIndented = true;
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
});

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "The TameMyCerts REST API",
        Description =
            "A simple, yet powerful REST API for submitting certificates to one or more Microsoft Directory Certificate Services (AD CS) certification authorities",
        Contact = new OpenApiContact
        {
            Name = "TameMyCerts REST API",
            Url = new Uri("https://github.com/Sleepw4lker/TameMyCerts.REST")
        },
        License = new OpenApiLicense
        {
            Name = "Project License",
            Url = new Uri("https://raw.githubusercontent.com/Sleepw4lker/TameMyCerts.REST/main/LICENSE")
        }
    });

    options.DescribeAllParametersInCamelCase();
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, $"{appName}.xml"));
});

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();

builder.Services.AddAuthorization(options =>
{
    // By default, all incoming requests will be authorized according to the default policy.
    options.FallbackPolicy = options.DefaultPolicy;
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseRewriter(new RewriteOptions().AddRedirect("^$", "swagger"));

app.UseHttpsRedirection();
app.UseHsts();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();