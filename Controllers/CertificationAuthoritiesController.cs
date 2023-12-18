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

using System.Runtime.InteropServices;
using System.Security.Principal;
using CERTCLILib;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Controllers;

/// <summary>
///     An API controller for all operations related to a certification authority.
/// </summary>
[Authorize]
[ApiController]
[Route("v1/certification-authorities")]
public class CertificationAuthoritiesController : ControllerBase
{
    private readonly ILogger<CertificationAuthoritiesController> _logger;

    public CertificationAuthoritiesController(ILogger<CertificationAuthoritiesController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    ///     Retrieves a collection of all available certification authorities.
    /// </summary>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    public async Task<ActionResult<CertificationAuthorityCollection>> GetAllCas(bool textualEncoding = false)
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Problem();
        }

        return new CertificationAuthorityCollection(new CertificationAuthorityCollection(textualEncoding)
            .CertificationAuthorities.Where(certificationAuthority =>
                certificationAuthority.AllowsForEnrollment(user)).ToList());
    }

    /// <summary>
    ///     Retrieves details for a certification authority.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    [Route("{caName}")]
    public async Task<ActionResult<CertificationAuthority>> GetCaByName(string caName, bool textualEncoding = false)
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Problem();
        }

        if (CertificationAuthority.Create(caName, textualEncoding) is not { } certificationAuthority)
        {
            return NotFound(string.Format(LocalizedStrings.DESC_MISSING_CA, caName));
        }

        if (!certificationAuthority.AllowsForEnrollment(user))
        {
            return Forbid(string.Format(LocalizedStrings.DESC_CA_DENIED, caName));
        }

        return certificationAuthority;
    }

    /// <summary>
    ///     Retrieves the current certification authority certificate for a certification authority.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    [Route("{caName}/ca-certificate")]
    public async Task<ActionResult<SubmissionResponse>> GetCaCertificate(string caName,
        bool textualEncoding = false)
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Problem();
        }

        if (CertificationAuthority.Create(caName, textualEncoding) is not { } certificationAuthority)
        {
            return NotFound(string.Format(LocalizedStrings.DESC_MISSING_CA, caName));
        }

        if (!certificationAuthority.AllowsForEnrollment(user))
        {
            return Forbid(string.Format(LocalizedStrings.DESC_CA_DENIED, caName));
        }

        var certRequestInterface = new CCertRequest();

        try
        {
            return certRequestInterface.GetCaCertificate(certificationAuthority.ConfigurationString, textualEncoding);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }

    /// <summary>
    ///     Retrieves the current certification authority exchange certificate for a certification authority.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    [Route("{caName}/ca-exchange-certificate")]
    public async Task<ActionResult<SubmissionResponse>> GetCaExchangeCertificate(string caName,
        bool textualEncoding = false)
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Problem();
        }

        if (CertificationAuthority.Create(caName, textualEncoding) is not { } certificationAuthority)
        {
            return NotFound(string.Format(LocalizedStrings.DESC_MISSING_CA, caName));
        }

        if (!certificationAuthority.AllowsForEnrollment(user))
        {
            return Forbid(string.Format(LocalizedStrings.DESC_CA_DENIED, caName));
        }

        var certRequestInterface = new CCertRequest();

        try
        {
            return certRequestInterface.GetCaCertificate(certificationAuthority.ConfigurationString,
                textualEncoding, true);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }

    /// <summary>
    ///     Retrieves a collection of certificate revocation list distribution points for a certification authority.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    [Route("{caName}/crl-distribution-points")]
    public async Task<ActionResult<CertificateRevocationListDistributionPointCollection>> GetCrlDp(string caName,
        bool textualEncoding = false)
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Problem();
        }

        if (CertificationAuthority.Create(caName, textualEncoding) is not { } certificationAuthority)
        {
            return NotFound(string.Format(LocalizedStrings.DESC_MISSING_CA, caName));
        }

        if (!certificationAuthority.AllowsForEnrollment(user))
        {
            return Forbid(string.Format(LocalizedStrings.DESC_CA_DENIED, caName));
        }

        var certRequestInterface = new CCertRequest();

        try
        {
            return certRequestInterface.GetCrlDpCollection(certificationAuthority.ConfigurationString,
                textualEncoding);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }

    /// <summary>
    ///     Retrieves a collection of authority information access distribution points for a certification authority.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    [Route("{caName}/authority-information-access")]
    public async Task<ActionResult<AuthorityInformationAccessCollection>> GetAia(string caName,
        bool textualEncoding = false)
    {
        if ((WindowsIdentity)HttpContext.User.Identity! is not { } user)
        {
            return Problem();
        }

        if (CertificationAuthority.Create(caName, textualEncoding) is not { } certificationAuthority)
        {
            return NotFound(string.Format(LocalizedStrings.DESC_MISSING_CA, caName));
        }

        if (!certificationAuthority.AllowsForEnrollment(user))
        {
            return Forbid(string.Format(LocalizedStrings.DESC_CA_DENIED, caName));
        }

        var certRequestInterface = new CCertRequest();

        try
        {
            return certRequestInterface.GetAiaCollection(certificationAuthority.ConfigurationString,
                textualEncoding);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }
}