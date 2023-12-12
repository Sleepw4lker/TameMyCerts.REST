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

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Http;
using TameMyCerts.REST.Models;
using CERTCLILib;

namespace TameMyCerts.REST.Controllers
{
    /// <summary>
    ///     An API controller for all operations related to PKIX certificates.
    /// </summary>
    public class CertificatesController : ApiController
    {
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
        [Route("v1/certificates/{caName}/{requestId}")]
        public SubmissionResponse GetCertificateByRequestId(string caName, int requestId,
            [FromUri] bool textualEncoding = false)
        {
            if (!(CertificationAuthority.Create(caName, textualEncoding) is CertificationAuthority
                    certificationAuthority))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA, caName))
                });
            }

            if (!certificationAuthority.AllowsForEnrollment((WindowsIdentity)User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED, caName))
                });
            }


            using (((WindowsIdentity)User.Identity).Impersonate())
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
            }
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
        [Route("v1/certificates/{caName}")]
        public SubmissionResponse SubmitCertificateRequest(string caName, CertificateRequest certificateRequest,
            [FromUri] string certificateTemplate = null,
            [FromUri] bool textualEncoding = false)
        {
            if (!(CertificationAuthority.Create(caName, textualEncoding) is CertificationAuthority
                    certificationAuthority))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA, caName))
                });
            }

            if (!certificationAuthority.AllowsForEnrollment((WindowsIdentity)User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED, caName))
                });
            }

            if (certificateRequest?.Request == null)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(LocalizedStrings.DESC_INVALID_REQUEST)
                });
            }

            var requestType = CertificateRequestIntegrityChecks.DetectRequestType(certificateRequest.Request,
                out var rawCertificateRequest);

            if (requestType == 0)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(LocalizedStrings.DESC_INVALID_CSR)
                });
            }

            var submissionFlags = CertCli.CR_IN_BASE64;
            submissionFlags |= CertCli.CR_IN_FULLRESPONSE;
            submissionFlags |= requestType;

            // may happen if RequestAttributes are passed without content
            if (certificateRequest.RequestAttributes == null)
            {
                certificateRequest.RequestAttributes = new List<string>();
            }

            if (certificateTemplate != null)
            {
                certificateRequest.RequestAttributes.Add($"CertificateTemplate:{certificateTemplate}");
            }

            using (((WindowsIdentity)User.Identity).Impersonate())
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
            }
        }
    }
}