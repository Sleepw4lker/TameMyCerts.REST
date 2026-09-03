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
///     An API controller for all operations related to a certification authority.
/// </summary>
[Authorize]
[ApiController]
[Route("v1/certification-authorities")]
public class CertificationAuthoritiesController : ControllerBase
{
    private readonly ICertificationAuthorityDirectory _caDirectory;
    private readonly ICertificationAuthorityGateway _gateway;

    /// <summary>
    ///     Builds the controller.
    /// </summary>
    /// <param name="gateway">The certification authority gateway to use.</param>
    /// <param name="caDirectory">The certification authority directory to use.</param>
    public CertificationAuthoritiesController(ICertificationAuthorityGateway gateway,
        ICertificationAuthorityDirectory caDirectory)
    {
        _gateway = gateway;
        _caDirectory = caDirectory;
    }

    /// <summary>
    ///     Retrieves a collection of all available certification authorities.
    /// </summary>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    public ActionResult<CertificationAuthorityCollection> GetAllCas(bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryGetIdentity(HttpContext.User.Identity, out var user, out var error))
        {
            return error;
        }

        return new CertificationAuthorityCollection(_caDirectory.GetAll(textualEncoding)
            .Where(certificationAuthority => certificationAuthority.AllowsForEnrollment(user))
            .ToList());
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
    public ActionResult<CertificationAuthority> GetCaByName(string caName, bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _caDirectory.FindByName(caName, textualEncoding),
                () => string.Format(LocalizedStrings.DESC_MISSING_CA, caName),
                _ => string.Format(LocalizedStrings.DESC_CA_DENIED, caName),
                out var certificationAuthority, out _, out var error))
        {
            return error;
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
    public ActionResult<SubmissionResponse> GetCaCertificate(string caName,
        bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _caDirectory.FindByName(caName, textualEncoding),
                () => string.Format(LocalizedStrings.DESC_MISSING_CA, caName),
                _ => string.Format(LocalizedStrings.DESC_CA_DENIED, caName),
                out var certificationAuthority, out _, out var error))
        {
            return error;
        }

        return _gateway.GetCaCertificate(certificationAuthority.ConfigurationString, textualEncoding);
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
    public ActionResult<SubmissionResponse> GetCaExchangeCertificate(string caName,
        bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _caDirectory.FindByName(caName, textualEncoding),
                () => string.Format(LocalizedStrings.DESC_MISSING_CA, caName),
                _ => string.Format(LocalizedStrings.DESC_CA_DENIED, caName),
                out var certificationAuthority, out _, out var error))
        {
            return error;
        }

        return _gateway.GetCaCertificate(certificationAuthority.ConfigurationString, textualEncoding, true);
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
    public ActionResult<CertificateRevocationListDistributionPointCollection> GetCrlDp(string caName,
        bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _caDirectory.FindByName(caName, textualEncoding),
                () => string.Format(LocalizedStrings.DESC_MISSING_CA, caName),
                _ => string.Format(LocalizedStrings.DESC_CA_DENIED, caName),
                out var certificationAuthority, out _, out var error))
        {
            return error;
        }

        return _gateway.GetCrlDpCollection(certificationAuthority.ConfigurationString, textualEncoding);
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
    public ActionResult<AuthorityInformationAccessCollection> GetAia(string caName,
        bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _caDirectory.FindByName(caName, textualEncoding),
                () => string.Format(LocalizedStrings.DESC_MISSING_CA, caName),
                _ => string.Format(LocalizedStrings.DESC_CA_DENIED, caName),
                out var certificationAuthority, out _, out var error))
        {
            return error;
        }

        return _gateway.GetAiaCollection(certificationAuthority.ConfigurationString, textualEncoding);
    }
}
