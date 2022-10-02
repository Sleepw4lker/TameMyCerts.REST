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
            try
            {
                return new CertificationAuthorityCollection(ActiveDirectory
                    .GetCertificationAuthorityCollection(textualEncoding).CertificationAuthorities
                    .Where(certificationAuthority =>
                        certificationAuthority.AllowsForEnrollment((WindowsIdentity) User.Identity))
                    .ToList());
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(ex.Message)
                });
            }
        }

        /// <summary>
        ///     Retrieves details for a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The common name of the target certification authority.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities/{certificationAuthority}")]
        public CertificationAuthority GetCaByName(string certificationAuthority, [FromUri] bool textualEncoding = false)
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

            return certificationAuthorityObject;
        }

        /// <summary>
        ///     Retrieves the current certification authority certificate for a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The common name of the target certification authority.</param>
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities/{certificationAuthority}/ca-certificate")]
        public SubmissionResponse GetCaCertificate(string certificationAuthority,
            [FromUri] bool includeCertificateChain = false, [FromUri] bool textualEncoding = false)
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
                var certRequestInterface = new CCertRequest();
                var result =
                    certRequestInterface.GetCaCertificate(certificationAuthorityObject.ConfigString,
                        includeCertificateChain, textualEncoding);
                Marshal.ReleaseComObject(certRequestInterface);
                return result;
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
        ///     Retrieves the current certification authority exchange certificate for a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The common name of the target certification authority.</param>
        /// <param name="includeCertificateChain">Causes the response to be a PKCS#7 container including the certificate chain.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities/{certificationAuthority}/ca-exchange-certificate")]
        public SubmissionResponse GetCaExchangeCertificate(string certificationAuthority,
            [FromUri] bool includeCertificateChain = false, [FromUri] bool textualEncoding = false)
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
                var certRequestInterface = new CCertRequest();
                var result = certRequestInterface.GetCaCertificate(certificationAuthorityObject.ConfigString,
                    includeCertificateChain,
                    textualEncoding, true);
                Marshal.ReleaseComObject(certRequestInterface);
                return result;
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
        ///     Retrieves a collection of certificate revocation list distribution points for a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The common name of the target certification authority.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities/{certificationAuthority}/crl-distribution-points")]
        public CertificateRevocationListDistributionPointCollection GetCrlDp(string certificationAuthority,
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
                var certRequestInterface = new CCertRequest();
                var result =
                    certRequestInterface.GetCrlDpCollection(certificationAuthorityObject.ConfigString, textualEncoding);
                Marshal.ReleaseComObject(certRequestInterface);
                return result;
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
        ///     Retrieves a collection of authority information access distribution points for a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The common name of the target certification authority.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certification-authorities/{certificationAuthority}/authority-information-access")]
        public AuthorityInformationAccessCollection GetAia(string certificationAuthority,
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
                var certRequestInterface = new CCertRequest();
                var result =
                    certRequestInterface.GetAiaCollection(certificationAuthorityObject.ConfigString, textualEncoding);
                Marshal.ReleaseComObject(certRequestInterface);
                return result;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED, ex.Message))
                });
            }
        }
    }
}