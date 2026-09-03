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

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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
    private readonly ICertificationAuthorityDirectory _caDirectory;
    private readonly ICertificateTemplateRepository _templateRepository;

    /// <summary>
    ///     Builds the controller.
    /// </summary>
    /// <param name="templateRepository">The certificate template repository to use.</param>
    /// <param name="caDirectory">The certification authority directory to use.</param>
    public CertificateTemplatesController(ICertificateTemplateRepository templateRepository,
        ICertificationAuthorityDirectory caDirectory)
    {
        _templateRepository = templateRepository;
        _caDirectory = caDirectory;
    }

    /// <summary>
    ///     Retrieves a collection of all certificate templates in the underlying Active Directory environment.
    /// </summary>
    [HttpGet]
    [Authorize]
    public ActionResult<CertificateTemplateCollection> GetCertificateTemplateCollection()
    {
        if (!EnrollmentAuthorizationGate.TryGetIdentity(HttpContext.User.Identity, out var user, out var error))
        {
            return error;
        }

        return new CertificateTemplateCollection(_templateRepository.GetAll()
            .Where(certificateTemplate => certificateTemplate.AllowsForEnrollment(user))
            .ToList());
    }

    /// <summary>
    ///     Retrieves details for a certificate template.
    /// </summary>
    /// <param name="templateName">The name of the target certificate template.</param>
    [HttpGet]
    [Authorize]
    [Route("{templateName}")]
    public ActionResult<CertificateTemplate> GetCertificateTemplate(string templateName)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _templateRepository.FindByName(templateName),
                null,
                _ => string.Format(LocalizedStrings.DESC_TEMPLATED_DENIED, templateName),
                out var certificateTemplate, out _, out var error))
        {
            return error;
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
    public ActionResult<CertificationAuthorityCollection> GetCertificateTemplateIssuers(string templateName,
        bool textualEncoding = false)
    {
        return new CertificationAuthorityCollection(_caDirectory.GetAll(textualEncoding)
            .Where(certificationAuthority =>
                certificationAuthority.CertificateTemplates.Contains(templateName,
                    StringComparer.InvariantCultureIgnoreCase))
            .ToList());
    }
}
