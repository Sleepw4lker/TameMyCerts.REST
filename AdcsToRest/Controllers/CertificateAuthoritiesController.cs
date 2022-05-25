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
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;
using CERTENROLLLib;

namespace AdcsToRest.Controllers
{
    public class CertificateAuthoritiesController : ApiController
    {
        /// <summary>
        ///     Retrieves a collection of all available certificate authorities.
        /// </summary>
        [HttpGet]
        [Authorize]
        [Route("ca")]
        public List<CertificateAuthority> GetCaInfoList()
        {
            return GetCertificateAuthorityList();
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
            var result = GetCertificateAuthority(caName);

            if (result == null)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA,
                        caName)),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_CA
                });
            }

            return result;
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
            var configString = GetConfigString(caName);
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
            var configString = GetConfigString(caName);
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
        public List<CertificateRevocationListDistributionPoint> GetCrl(string caName)
        {
            var configString = GetConfigString(caName);
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
        public List<AuthorityInformationAccess> GetAis(string caName)
        {
            var configString = GetConfigString(caName);
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
            var configString = GetConfigString(caName);

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
            if (!VerifyCertificateRequest(certificateRequest.Request, certificateRequest.RequestType,
                    out var rawCertificateRequest))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content =
                        new StringContent(string.Format(LocalizedStrings.DESC_INVALID_CSR,
                            $"0x{certificateRequest.RequestType:X}")),
                    ReasonPhrase = LocalizedStrings.ERR_INVALID_CSR
                });
            }

            var configString = GetConfigString(caName);
            var submissionFlags = CertCli.CR_IN_BASE64;
            submissionFlags |= certificateRequest.RequestType;

            using (((WindowsIdentity) User.Identity).Impersonate())
            {
                var certRequestInterface = new CCertRequest();
                return certRequestInterface.Submit2(configString, rawCertificateRequest,
                    certificateRequest.RequestAttributes,
                    submissionFlags, includeCertificateChain);
            }
        }

        /// <summary>
        ///     Verifies if the certificate request can be parsed as defined by the requestType.
        /// </summary>
        /// <param name="certificateRequest">The certificate request in BASE64 format, with or without headers.</param>
        /// <param name="requestType">The request type specifies how the certificate request is to be interpreted.</param>
        /// <param name="rawCertificateRequest">
        ///     Harmonized certificate request, returned as BASE64 without header, regardless of
        ///     the given input.
        /// </param>
        /// <returns></returns>
        private static bool VerifyCertificateRequest(string certificateRequest, int requestType,
            out string rawCertificateRequest)
        {
            rawCertificateRequest = null;

            switch (requestType)
            {
                case CertCli.CR_IN_PKCS10:

                    var certRequestPkcs10 =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

                    try
                    {
                        certRequestPkcs10.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );
                        rawCertificateRequest = certRequestPkcs10.RawData;
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestPkcs10);
                    }

                    break;

                case CertCli.CR_IN_PKCS7:

                    var certRequestPkcs7 =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                    try
                    {
                        certRequestPkcs7.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );
                        rawCertificateRequest = certRequestPkcs7.RawData;
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestPkcs7);
                    }

                    break;

                case CertCli.CR_IN_CMC:

                    var certRequestCmc =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                    try
                    {
                        certRequestCmc.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );
                        rawCertificateRequest = certRequestCmc.RawData;
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestCmc);
                    }

                    break;

                default:

                    return false;
            }

            return true;
        }

        private static CertificateAuthority GetCertificateAuthority(string certificateAuthority)
        {
            var searchResults = GetEnrollmentServiceCollection(certificateAuthority);

            return searchResults.Count == 1 ? new CertificateAuthority(searchResults[0]) : null;
        }

        private static List<CertificateAuthority> GetCertificateAuthorityList()
        {
            var searchResults = GetEnrollmentServiceCollection();

            var caInfoList = new List<CertificateAuthority>();

            foreach (SearchResult searchResult in searchResults)
            {
                caInfoList.Add(new CertificateAuthority(searchResult));
            }

            return caInfoList;
        }

        private static string GetCertificateAuthorityServerName(string certificateAuthority)
        {
            var searchResults = GetEnrollmentServiceCollection(certificateAuthority);

            return searchResults.Count == 1 ? searchResults[0].Properties["dNSHostName"][0].ToString() : null;
        }

        private static SearchResultCollection GetEnrollmentServiceCollection(string cn = null)
        {
            var domainPath = GetForestRootDomain();

            if (domainPath == null)
            {
                return null;
            }

            var additionalCriteria = string.Empty;

            if (cn != null)
            {
                additionalCriteria += $"(cn={cn})";
            }

            var enrollmentContainer =
                $"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{domainPath}";

            var directoryEntry = new DirectoryEntry(enrollmentContainer);

            var directorySearcher = new DirectorySearcher(directoryEntry)
            {
                Filter = $"(&{additionalCriteria}(objectCategory=pKIEnrollmentService))",
                Sort = new SortOption("cn", SortDirection.Ascending),
                PropertiesToLoad = { "cn", "certificateTemplates", "dNSHostName" }
            };

            return directorySearcher.FindAll();
        }

        private static string GetConfigString(string certificateAuthority)
        {
            var certificateAuthorityServerName = GetCertificateAuthorityServerName(certificateAuthority);

            if (null == certificateAuthorityServerName)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA,
                        certificateAuthority)),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_CA
                });
            }

            return $"{certificateAuthorityServerName}\\{certificateAuthority}";
        }

        private static string GetForestRootDomain()
        {
            try
            {
                var directoryEntry = new DirectoryEntry("LDAP://RootDSE");
                return directoryEntry.Properties["rootDomainNamingContext"][0].ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}