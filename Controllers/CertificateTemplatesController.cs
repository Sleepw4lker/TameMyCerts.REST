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

using System.Security.Principal;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TameMyCerts.NetCore.Common.Models;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Controllers;

/// <summary>
///     An API controller for all operations related to certificate templates.
/// </summary>
[Authorize]
[ApiController]
[Route("v1/certificate-templates")]
public class CertificateTemplatesController : ControllerBase
{
    private readonly ILogger<CertificateTemplatesController> _logger;

    public CertificateTemplatesController(ILogger<CertificateTemplatesController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    ///     Retrieves a collection of all certificate templates in the underlying Active Directory environment.
    /// </summary>
    [HttpGet]
    [Authorize]
    public async Task<ActionResult<CertificateTemplateCollection>> GetCertificateTemplateCollection()
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Problem();
        }

        return new CertificateTemplateCollection(new CertificateTemplateCollection().CertificateTemplates
            .Where(certificateTemplate => certificateTemplate!.AllowsForEnrollment(user))
            .ToList());
    }

    /// <summary>
    ///     Retrieves details for a certificate template.
    /// </summary>
    /// <param name="templateName">The name of the target certificate template.</param>
    [HttpGet]
    [Authorize]
    [Route("{templateName}")]
    public async Task<ActionResult<CertificateTemplate>> GetCertificateTemplate(string templateName)
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Forbid();
        }

        if (CertificateTemplate.Create(templateName) is not { } certificateTemplate)
        {
            return NotFound();
        }

        if (!certificateTemplate.AllowsForEnrollment(user))
        {
            return Forbid(string.Format(LocalizedStrings.DESC_TEMPLATED_DENIED, templateName));
        }

        return certificateTemplate;
    }

    /// <summary>
    ///     Retrieves a collection of certification authorities that issue certificates for a given certificate template.
    /// </summary>
    /// <param name="templateName">The name of the target certificate template.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    [Route("{templateName}/issuers")]
    public async Task<ActionResult<CertificationAuthorityCollection>> GetCertificateTemplateIssuers(string templateName,
        bool textualEncoding = false)
    {
        return new CertificationAuthorityCollection(new CertificationAuthorityCollection(textualEncoding)
            .CertificationAuthorities.Where(
                certificationAuthority =>
                    certificationAuthority.CertificateTemplates.Contains(templateName,
                        StringComparer.InvariantCultureIgnoreCase)).ToList());
    }
}