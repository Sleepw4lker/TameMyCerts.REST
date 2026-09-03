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
using TameMyCerts.NetCore.Common.Enums;
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
    private readonly ILogger<CertificatesController> _logger;

    public CertificatesController(ILogger<CertificatesController> logger)
    {
        _logger = logger;
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
    public async Task<ActionResult<SubmissionResponse>> GetCertificateByRequestId(string caName, int requestId,
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

        var result = WindowsIdentity.RunImpersonated(user.AccessToken, () =>
        {
            var certRequestInterface = new CCertRequest();

            try
            {
                return certRequestInterface.RetrievePending(certificationAuthority.ConfigurationString, requestId,
                    textualEncoding);
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        });

        return result;
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
    public async Task<ActionResult<SubmissionResponse>> SubmitCertificateRequest(string caName,
        CertificateRequest certificateRequest, string? certificateTemplate = null, bool textualEncoding = false)
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

        var result = WindowsIdentity.RunImpersonated(user.AccessToken, () =>
        {
            var certRequestInterface = new CCertRequest();

            try
            {
                return certRequestInterface.Submit(certificationAuthority.ConfigurationString,
                    rawCertificateRequest, certificateRequest.RequestAttributes, submissionFlags,
                    textualEncoding);
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        });

        return result;
    }
}