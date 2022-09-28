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

using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using AdcsToRest.Models;

namespace AdcsToRest
{
    /// <summary>
    ///     A class holding methods that help acquiring PKI related information from Active Directory.
    /// </summary>
    public static class ActiveDirectory
    {
        /// <summary>
        ///     Retrieves a certification authority and the templates bound to it from Active Directory.
        /// </summary>
        /// <param name="certificationAuthority">The name of the target certification authority.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        /// <exception cref="HttpResponseException">
        ///     Throws a HTTP 404 error if the specified certification authority was not found in Active Directory.
        /// </exception>
        public static CertificationAuthority GetCertificationAuthority(string certificationAuthority,
            bool textualEncoding = false)
        {
            var searchResults = GetEnrollmentServiceCollection(certificationAuthority);

            if (searchResults.Count != 1)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA,
                        certificationAuthority))
                });
            }

            return new CertificationAuthority(searchResults[0], textualEncoding);
        }

        /// <summary>
        ///     Retrieves a list of all certification authorities in the Active Directory forest, and the templates bound to each.
        /// </summary>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        public static CertificationAuthorityCollection GetCertificationAuthorityCollection(
            bool textualEncoding = false)
        {
            var searchResults = GetEnrollmentServiceCollection();

            return new CertificationAuthorityCollection((from SearchResult searchResult in searchResults
                select new CertificationAuthority(searchResult, textualEncoding)).ToList());
        }

        /// <summary>
        ///     Retrieves the configuration string for a certification authority.
        /// </summary>
        /// <param name="certificationAuthority">The name of the target certification authority.</param>
        /// <returns>The configuration string, built from the CA's DNS name and the CA common name.</returns>
        /// <exception cref="HttpResponseException">
        ///     Throws a HTTP 404 error if the specified certification authority was not found in
        ///     Active Directory.
        /// </exception>
        public static string GetConfigString(string certificationAuthority)
        {
            var certificationAuthorityServerName = GetCertificationAuthorityServerName(certificationAuthority);

            if (null == certificationAuthorityServerName)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA,
                        certificationAuthority))
                });
            }

            return $"{certificationAuthorityServerName}\\{certificationAuthority}";
        }

        private static string GetCertificationAuthorityServerName(string certificationAuthority)
        {
            var searchResults = GetEnrollmentServiceCollection(certificationAuthority);

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
                PropertiesToLoad = {"cn", "certificateTemplates", "dNSHostName", "cACertificate"}
            };

            return directorySearcher.FindAll();
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

        private static SearchResultCollection GetCertificateTemplateSearchResults(string cn = null)
        {
            var domainPath = GetForestRootDomain();

            if (null == domainPath)
            {
                return null;
            }

            var additionalCriteria = string.Empty;

            if (cn != null)
            {
                additionalCriteria += $"(cn={cn})";
            }

            var enrollmentContainer =
                $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{domainPath}";

            var directoryEntry = new DirectoryEntry(enrollmentContainer);

            var directorySearcher = new DirectorySearcher(directoryEntry)
            {
                Filter =
                    $"(&{additionalCriteria}(objectCategory=pKICertificateTemplate)(msPKI-Template-Schema-Version>=2))",
                Sort = new SortOption("cn", SortDirection.Ascending),
                PropertiesToLoad =
                {
                    "cn",
                    "msPKI-minimal-Key-Size",
                    "revision",
                    "msPKI-Template-Minor-Revision",
                    "msPKI-Cert-Template-OID",
                    "msPKI-Certificate-Application-Policy",
                    "msPKI-RA-Application-Policies"
                }
            };

            return directorySearcher.FindAll();
        }

        /// <summary>
        ///     Retrieves information for a single certificate template from the directory.
        /// </summary>
        /// <param name="certificateTemplate"></param>
        /// <returns>A CertificateTemplate Object.</returns>
        /// <exception cref="HttpResponseException">
        ///     Throws a HTTP 404 error when no certificate template with the given name was
        ///     found in the directory.
        /// </exception>
        public static CertificateTemplate GetCertificateTemplate(string certificateTemplate)
        {
            var searchResults = GetCertificateTemplateSearchResults(certificateTemplate);

            if (searchResults.Count != 1)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_TEMPLATE,
                        certificateTemplate))
                });
            }

            return new CertificateTemplate(searchResults[0]);
        }

        /// <summary>
        ///     Retrieves information for all certificate templates from the directory.
        /// </summary>
        /// <returns>A CertificateTemplateCollection Object.</returns>
        public static CertificateTemplateCollection GetCertificateTemplateCollection()
        {
            var searchResults = GetCertificateTemplateSearchResults();

            return new CertificateTemplateCollection((from SearchResult searchResult in searchResults
                select new CertificateTemplate(searchResult)).ToList());
        }
    }
}