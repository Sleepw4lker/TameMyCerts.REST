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
using System.Security.Principal;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest.Controllers
{
    public class CertificateAuthorityController : ApiController
    {
        /// <summary>
        ///     Retrieves a collection of all available certificate authorities.
        /// </summary>
        [HttpGet]
        [Authorize]
        [Route("ca")]
        public List<CertificateAuthority> GetCaInfoList()
        {
            return ActiveDirectory.GetCertificateAuthorityList();
        }

        /// <summary>
        ///     Retrieves details for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        [HttpGet]
        [Authorize]
        [Route("ca/{caName}")]
        public CertificateAuthority GetCaInfo(string caName)
        {
            return ActiveDirectory.GetCertificateAuthority(caName);
        }

        /// <summary>
        ///     Retrieves the current certificate authority certificate for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="includeCertificateChain">
        ///     When set to true, the Certificate response property will be a PKCS#7 container including the certificate chain
        ///     instead of a plain certificate.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("ca/{caName}/ca-certificate")]
        public SubmissionResponse GetCaCertificate(string caName,
            [FromUri] bool includeCertificateChain = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            return certRequestInterface.GetCaCertificate2(configString, includeCertificateChain);
        }

        /// <summary>
        ///     Retrieves the current certificate authority exchange certificate for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="includeCertificateChain">
        ///     When set to true, the Certificate response property will be a PKCS#7 container including the certificate chain
        ///     instead of a plain certificate.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("ca/{caName}/ca-exchange-certificate")]
        public SubmissionResponse GetCaExchangeCertificate(string caName,
            [FromUri] bool includeCertificateChain = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            return certRequestInterface.GetCaCertificate2(configString, includeCertificateChain, true);
        }

        /// <summary>
        ///     Retrieves a collection of certificate revocation list distribution points for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <returns></returns>
        [HttpGet]
        [Authorize]
        [Route("ca/{caName}/crldp")]
        public List<CertificateRevocationListDistributionPoint> GetCrlDp(string caName)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            return certRequestInterface.GetCrlDpCollection(configString);
        }

        /// <summary>
        ///     Retrieves a collection of authority information access distribution points for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <returns></returns>
        [HttpGet]
        [Authorize]
        [Route("ca/{caName}/aia")]
        public List<AuthorityInformationAccess> GetAia(string caName)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            return certRequestInterface.GetAiaCollection(configString);
        }

        /// <summary>
        ///     Retrieves an issued certificate from a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="requestId">The request ID of the certificate to retrieve.</param>
        /// <param name="includeCertificateChain">
        ///     When set to true, the Certificate response property will be a PKCS#7 container including the certificate chain
        ///     instead of a plain certificate.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("ca/{caName}/request/{requestId}")]
        public SubmissionResponse Get(string caName, int requestId,
            [FromUri] bool includeCertificateChain = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);

            using (((WindowsIdentity) User.Identity).Impersonate())
            {
                var certRequestInterface = new CCertRequest();
                return certRequestInterface.RetrievePending2(configString, requestId, includeCertificateChain);
            }
        }

        /// <summary>
        ///     Submits a certificate signing request to a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="certificateRequest">The data structure containing the certificate request and optional settings.</param>
        /// <param name="includeCertificateChain">
        ///     When set to true, the Certificate response property will be a PKCS#7 container including the certificate chain
        ///     instead of a plain certificate.
        /// </param>
        [HttpPost]
        [Authorize]
        [Route("ca/{caName}/request")]
        public SubmissionResponse PostCertificateRequest(string caName,
            CertificateRequest certificateRequest,
            [FromUri] bool includeCertificateChain = false)
        {
            var requestType = CertificateRequestIntegrityChecks.AutoDetectRequestType(certificateRequest.Request,
                out var rawCertificateRequest);

            if (requestType == 0)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_INVALID_CSR)),
                    ReasonPhrase = LocalizedStrings.ERR_INVALID_CSR
                });
            }

            var configString = ActiveDirectory.GetConfigString(caName);
            var submissionFlags = CertCli.CR_IN_BASE64;
            submissionFlags |= requestType;

            using (((WindowsIdentity) User.Identity).Impersonate())
            {
                var certRequestInterface = new CCertRequest();
                return certRequestInterface.Submit2(configString, rawCertificateRequest,
                    certificateRequest.RequestAttributes,
                    submissionFlags, includeCertificateChain);
            }
        }
    }
}