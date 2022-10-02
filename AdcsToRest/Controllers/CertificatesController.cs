// Copyright 2022 Uwe Gradenegger

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest.Controllers
{
    /// <summary>
    ///     An API controller for all operations related to PKIX certificates.
    /// </summary>
    public class CertificatesController : ApiController
    {
        /// <summary>
        ///     Retrieves an issued certificate from a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The common name of the target certification authority.</param>
        /// <param name="requestId">The request identifier of the certificate to retrieve.</param>
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certificates/{certificationAuthority}/{requestId}")]
        public SubmissionResponse GetCertificateByRequestId(string certificationAuthority, int requestId,
            [FromUri] bool includeCertificateChain = false,
            [FromUri] bool textualEncoding = false)
        {
            CertificationAuthority certificationAuthorityObject;

            try
            {
                certificationAuthorityObject =
                    ActiveDirectory.GetCertificationAuthority(certificationAuthority, textualEncoding);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(ex.Message)
                });
            }

            if (!certificationAuthorityObject.AllowsForEnrollment((WindowsIdentity) User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED,
                        certificationAuthority))
                });
            }

            try
            {
                using (((WindowsIdentity) User.Identity).Impersonate())
                {
                    var certRequestInterface = new CCertRequest();
                    var result = certRequestInterface.RetrievePending(certificationAuthorityObject.ConfigString,
                        requestId, includeCertificateChain,
                        textualEncoding);
                    Marshal.ReleaseComObject(certRequestInterface);
                    return result;
                }
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED, ex.Message))
                });
            }
        }

        /// <summary>
        ///     Submits a certificate signing request to a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The common name of the target certification authority.</param>
        /// <param name="certificateRequest">The data structure containing the certificate request and optional settings.</param>
        /// <param name="certificateTemplate">The certificate template the certificate request shall be assigned to.</param>
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpPost]
        [Authorize]
        [Route("v1/certificates/{certificationAuthority}")]
        public SubmissionResponse SubmitCertificateRequest(string certificationAuthority,
            CertificateRequest certificateRequest,
            [FromUri] string certificateTemplate = null,
            [FromUri] bool includeCertificateChain = false,
            [FromUri] bool textualEncoding = false)
        {
            CertificationAuthority certificationAuthorityObject;

            try
            {
                certificationAuthorityObject =
                    ActiveDirectory.GetCertificationAuthority(certificationAuthority, textualEncoding);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(ex.Message)
                });
            }

            if (!certificationAuthorityObject.AllowsForEnrollment((WindowsIdentity) User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED,
                        certificationAuthority))
                });
            }

            try
            {
                var requestType = CertificateRequestIntegrityChecks.DetectRequestType(certificateRequest.Request,
                    out var rawCertificateRequest);

                var submissionFlags = CertCli.CR_IN_BASE64;
                submissionFlags |= requestType;

                if (certificateTemplate != null)
                {
                    certificateRequest.RequestAttributes.Add($"CertificateTemplate:{certificateTemplate}");
                }

                // Enroll with identity of logged on user
                using (((WindowsIdentity) User.Identity).Impersonate())
                {
                    var certRequestInterface = new CCertRequest();
                    var result = certRequestInterface.Submit(certificationAuthorityObject.ConfigString,
                        rawCertificateRequest,
                        certificateRequest.RequestAttributes, submissionFlags, includeCertificateChain,
                        textualEncoding);
                    Marshal.ReleaseComObject(certRequestInterface);
                    return result;
                }
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(ex.Message)
                });
            }
        }
    }
}