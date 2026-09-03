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
using TameMyCerts.REST.Enums;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Controllers;

/// <summary>
///     An API controller for all operations related to PKIX certificates.
/// </summary>
[Authorize]
[ApiController]
[Route("v1/certificates")]
public class CertificatesController : ControllerBase
{
    private readonly ICertificationAuthorityDirectory _caDirectory;
    private readonly ICertificationAuthorityGateway _gateway;

    /// <summary>
    ///     Builds the controller.
    /// </summary>
    /// <param name="gateway">The certification authority gateway to use.</param>
    /// <param name="caDirectory">The certification authority directory to use.</param>
    public CertificatesController(ICertificationAuthorityGateway gateway, ICertificationAuthorityDirectory caDirectory)
    {
        _gateway = gateway;
        _caDirectory = caDirectory;
    }

    /// <summary>
    ///     Retrieves an issued certificate from a certification authority.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="requestId">The request identifier of the certificate to retrieve.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpGet]
    [Authorize]
    [Route("{caName}/{requestId}")]
    public ActionResult<SubmissionResponse> GetCertificateByRequestId(string caName, int requestId,
        bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _caDirectory.FindByName(caName, textualEncoding),
                () => string.Format(LocalizedStrings.DESC_MISSING_CA, caName),
                _ => string.Format(LocalizedStrings.DESC_CA_DENIED, caName),
                out var certificationAuthority, out var user, out var error))
        {
            return error;
        }

        return _gateway.RetrievePending(certificationAuthority.ConfigurationString, requestId, user,
            textualEncoding);
    }

    /// <summary>
    ///     Submits a certificate signing request to a certification authority.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="certificateRequest">The data structure containing the certificate request and optional settings.</param>
    /// <param name="certificateTemplate">The certificate template the certificate request shall be assigned to.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    [HttpPost]
    [Authorize]
    [Route("{caName}")]
    public ActionResult<SubmissionResponse> SubmitCertificateRequest(string caName,
        CertificateRequest certificateRequest, string? certificateTemplate = null, bool textualEncoding = false)
    {
        if (!EnrollmentAuthorizationGate.TryAuthorize(
                HttpContext.User.Identity,
                () => _caDirectory.FindByName(caName, textualEncoding),
                () => string.Format(LocalizedStrings.DESC_MISSING_CA, caName),
                _ => string.Format(LocalizedStrings.DESC_CA_DENIED, caName),
                out var certificationAuthority, out var user, out var error))
        {
            return error;
        }

        if (certificateRequest?.Request == null)
        {
            return BadRequest(LocalizedStrings.DESC_INVALID_REQUEST);
        }

        var requestType = CertificateRequestIntegrityChecks.DetectRequestType(certificateRequest.Request,
            out var rawCertificateRequest);

        if (requestType == 0)
        {
            return BadRequest(LocalizedStrings.DESC_INVALID_CSR);
        }

        var submissionFlags = CertCli.CR_IN_BASE64;
        submissionFlags |= CertCli.CR_IN_FULLRESPONSE;
        submissionFlags |= requestType;

        // may happen if RequestAttributes are passed without content
        certificateRequest.RequestAttributes ??= [];

        if (certificateTemplate != null)
        {
            certificateRequest.RequestAttributes.Add($"CertificateTemplate:{certificateTemplate}");
        }

        return _gateway.Submit(certificationAuthority.ConfigurationString, rawCertificateRequest,
            certificateRequest.RequestAttributes, submissionFlags, user, textualEncoding);
    }

    /// <summary>
    ///     Revokes a previously issued certificate.
    /// </summary>
    /// <param name="caName">The common name of the target certification authority.</param>
    /// <param name="revocationRequest">The data structure describing the certificate to revoke.</param>
    [HttpPost]
    [Authorize]
    [Route("{caName}/revoke")]
    public ActionResult RevokeCertificate(string caName, RevocationRequest revocationRequest)
    {
        if (!EnrollmentAuthorizationGate.TryGetIdentity(HttpContext.User.Identity, out var user, out var error))
        {
            return error;
        }

        // Deliberately does not go through EnrollmentAuthorizationGate.TryAuthorize/AllowsForEnrollment here:
        // revoking requires the CA's "Issue and Manage Certificates" permission, not the "Request Certificates"
        // (Enroll) permission that check evaluates - a different ACL entirely. That permission is enforced by
        // the certification authority itself, server-side, via the DCOM impersonation RevokeCertificate runs
        // under below - the same mechanism Submit already relies on for enrollment permission, just checking a
        // different right.
        if (_caDirectory.FindByName(caName) is not { } certificationAuthority)
        {
            return NotFound(string.Format(LocalizedStrings.DESC_MISSING_CA, caName));
        }

        if (string.IsNullOrEmpty(revocationRequest?.SerialNumber))
        {
            return BadRequest(LocalizedStrings.DESC_INVALID_REQUEST);
        }

        _gateway.RevokeCertificate(certificationAuthority.ConfigurationString, revocationRequest.SerialNumber,
            revocationRequest.Reason, user);

        return NoContent();
    }
}
