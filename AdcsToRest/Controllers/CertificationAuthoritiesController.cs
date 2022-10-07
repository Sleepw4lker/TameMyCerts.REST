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
using System.Linq;
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
    ///     An API controller for all operations related to a certification authority.
    /// </summary>
    public class CertificationAuthoritiesController : ApiController
    {
        /// <summary>
        ///     Retrieves a collection of all available certification authorities.
        /// </summary>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities")]
        public CertificationAuthorityCollection GetAllCas([FromUri] bool textualEncoding = false)
        {
            return new CertificationAuthorityCollection(new CertificationAuthorityCollection(textualEncoding)
                .CertificationAuthorities.Where(certificationAuthority =>
                    certificationAuthority.AllowsForEnrollment((WindowsIdentity) User.Identity)).ToList());
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
        [Route("v1/certification-authorities/{caName}")]
        public CertificationAuthority GetCaByName(string caName, [FromUri] bool textualEncoding = false)
        {
            if (!(CertificationAuthority.Create(caName, textualEncoding) is CertificationAuthority
                    certificationAuthority))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA, caName))
                });
            }

            if (!certificationAuthority.AllowsForEnrollment((WindowsIdentity) User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED,
                        caName))
                });
            }

            return certificationAuthority;
        }

        /// <summary>
        ///     Retrieves the current certification authority certificate for a certification authority.
        /// </summary>
        /// <param name="caName">The common name of the target certification authority.</param>
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities/{caName}/ca-certificate")]
        public SubmissionResponse GetCaCertificate(string caName,
            [FromUri] bool includeCertificateChain = false, [FromUri] bool textualEncoding = false)
        {
            if (!(CertificationAuthority.Create(caName, textualEncoding) is CertificationAuthority
                    certificationAuthority))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA, caName))
                });
            }

            if (!certificationAuthority.AllowsForEnrollment((WindowsIdentity) User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED,
                        caName))
                });
            }

            var certRequestInterface = new CCertRequest();

            try
            {
                var submissionResponse =
                    certRequestInterface.GetCaCertificate(certificationAuthority.ConfigurationString,
                        includeCertificateChain, textualEncoding);

                return submissionResponse;
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
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities/{caName}/ca-exchange-certificate")]
        public SubmissionResponse GetCaExchangeCertificate(string caName,
            [FromUri] bool includeCertificateChain = false, [FromUri] bool textualEncoding = false)
        {
            if (!(CertificationAuthority.Create(caName, textualEncoding) is CertificationAuthority
                    certificationAuthority))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA, caName))
                });
            }

            if (!certificationAuthority.AllowsForEnrollment((WindowsIdentity) User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED,
                        caName))
                });
            }

            var certRequestInterface = new CCertRequest();

            try
            {
                var submissionResponse = certRequestInterface.GetCaCertificate(
                    certificationAuthority.ConfigurationString,
                    includeCertificateChain,
                    textualEncoding, true);

                return submissionResponse;
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
        [Route("v1/certification-authorities/{caName}/crl-distribution-points")]
        public CertificateRevocationListDistributionPointCollection GetCrlDp(string caName,
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

            if (!certificationAuthority.AllowsForEnrollment((WindowsIdentity) User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED, caName))
                });
            }

            var certRequestInterface = new CCertRequest();

            try
            {
                var certificateRevocationListDistributionPointCollection =
                    certRequestInterface.GetCrlDpCollection(certificationAuthority.ConfigurationString,
                        textualEncoding);

                return certificateRevocationListDistributionPointCollection;
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
        [Route("v1/certification-authorities/{caName}/authority-information-access")]
        public AuthorityInformationAccessCollection GetAia(string caName,
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

            if (!certificationAuthority.AllowsForEnrollment((WindowsIdentity) User.Identity))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_CA_DENIED, caName))
                });
            }

            var certRequestInterface = new CCertRequest();

            try
            {
                var authorityInformationAccessCollection =
                    certRequestInterface.GetAiaCollection(certificationAuthority.ConfigurationString, textualEncoding);
                return authorityInformationAccessCollection;
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        }
    }
}