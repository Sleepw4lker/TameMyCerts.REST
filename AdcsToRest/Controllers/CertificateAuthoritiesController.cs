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
using System.Runtime.InteropServices;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest.Controllers
{
    /// <summary>
    ///     An API controller for all operations related to a certificate authority.
    /// </summary>
    public class CertificateAuthoritiesController : ApiController
    {
        /// <summary>
        ///     Retrieves a collection of all available certificate authorities.
        /// </summary>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-authorities")]
        public CertificateAuthorityCollection GetAllCas([FromUri] bool prettyPrintCertificate = false)
        {
            return ActiveDirectory.GetCertificateAuthorityCollection(prettyPrintCertificate);
        }

        /// <summary>
        ///     Retrieves details for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-authorities/{caName}")]
        public CertificateAuthority GetCaByName(string caName, [FromUri] bool prettyPrintCertificate = false)
        {
            return ActiveDirectory.GetCertificateAuthority(caName, prettyPrintCertificate);
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
        [Route("v1/certificate-authorities/{caName}/ca-certificate")]
        public SubmissionResponse GetCaCertificate(string caName,
            [FromUri] bool includeCertificateChain = false, [FromUri] bool prettyPrintCertificate = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            var result =
                certRequestInterface.GetCaCertificate(configString, includeCertificateChain, prettyPrintCertificate);
            Marshal.ReleaseComObject(certRequestInterface);
            return result;
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
        [Route("v1/certificate-authorities/{caName}/ca-exchange-certificate")]
        public SubmissionResponse GetCaExchangeCertificate(string caName,
            [FromUri] bool includeCertificateChain = false, [FromUri] bool prettyPrintCertificate = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            var result = certRequestInterface.GetCaCertificate(configString, includeCertificateChain,
                prettyPrintCertificate, true);
            Marshal.ReleaseComObject(certRequestInterface);
            return result;
        }


        /// <summary>
        ///     Retrieves a collection of certificate revocation list distribution points for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-authorities/{caName}/crl-distribution-points")]
        public List<CertificateRevocationListDistributionPoint> GetCrlDp(string caName,
            [FromUri] bool prettyPrintCertificate = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            var result = certRequestInterface.GetCrlDpCollection(configString, prettyPrintCertificate);
            Marshal.ReleaseComObject(certRequestInterface);
            return result;
        }

        /// <summary>
        ///     Retrieves a collection of authority information access distribution points for a certificate authority.
        /// </summary>
        /// <param name="caName">The common name of the target certificate authority.</param>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-authorities/{caName}/authority-information-access")]
        public List<AuthorityInformationAccess> GetAia(string caName, [FromUri] bool prettyPrintCertificate = false)
        {
            var configString = ActiveDirectory.GetConfigString(caName);
            var certRequestInterface = new CCertRequest();
            var result = certRequestInterface.GetAiaCollection(configString, prettyPrintCertificate);
            Marshal.ReleaseComObject(certRequestInterface);
            return result;
        }
    }
}