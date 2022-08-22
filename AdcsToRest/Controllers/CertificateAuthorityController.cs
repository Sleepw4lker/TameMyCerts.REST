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
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest.Controllers
{
    /// <summary>
    ///     An API controller for all operations related to a certificate authority.
    /// </summary>
    public class CertificateAuthorityController : ApiController
    {
        /// <summary>
        ///     Retrieves a collection of all available certificate authorities.
        /// </summary>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        [HttpGet]
        [Authorize]
        public CertificateAuthorityCollection GetAllCas([FromUri] bool prettyPrintCertificate = false)
        {
            return ActiveDirectory.GetCertificateAuthorityList(prettyPrintCertificate);
        }

        /// <summary>
        ///     Retrieves details for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        [HttpGet]
        [Authorize]
        public CertificateAuthority GetCaByName(string caName, [FromUri] bool prettyPrintCertificate = false)
        {
            return ActiveDirectory.GetCertificateAuthority(caName, prettyPrintCertificate);
        }

        /// <summary>
        ///     Retrieves an issued certificate from a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="requestId">The request ID of the certificate to retrieve.</param>
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        [HttpGet]
        [Authorize]
        public SubmissionResponse GetCertificateByRequestId(string caName, int requestId,
            [FromUri] bool includeCertificateChain = false,
            [FromUri] bool prettyPrintCertificate = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);

            using (((WindowsIdentity) User.Identity).Impersonate())
            {
                var certRequestInterface = new CCertRequest();
                var result = certRequestInterface.RetrievePending(configString, requestId, includeCertificateChain,
                    prettyPrintCertificate);
                Marshal.ReleaseComObject(certRequestInterface);
                return result;
            }
        }

        /// <summary>
        ///     Submits a certificate signing request to a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="certificateRequest">The data structure containing the certificate request and optional settings.</param>
        /// <param name="certificateTemplate">The certificate template the certificate request shall be assigned to.</param>
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        [HttpPost]
        [Authorize]
        public SubmissionResponse SubmitCertificateRequest(string caName,
            CertificateRequest certificateRequest,
            [FromUri] string certificateTemplate = null,
            [FromUri] bool includeCertificateChain = false,
            [FromUri] bool prettyPrintCertificate = false)
        {
            var requestType = CertificateRequestIntegrityChecks.DetectRequestType(certificateRequest.Request,
                out var rawCertificateRequest);

            var configString = ActiveDirectory.GetConfigString(caName);
            var submissionFlags = CertCli.CR_IN_BASE64;
            submissionFlags |= requestType;

            if (certificateTemplate != null)
            {
                certificateRequest.RequestAttributes.Add($"CertificateTemplate:{certificateTemplate}");
            }

            using (((WindowsIdentity) User.Identity).Impersonate())
            {
                var certRequestInterface = new CCertRequest();
                var result = certRequestInterface.Submit(configString, rawCertificateRequest,
                    certificateRequest.RequestAttributes, submissionFlags, includeCertificateChain,
                    prettyPrintCertificate);
                Marshal.ReleaseComObject(certRequestInterface);
                return result;
            }
        }
    }
}