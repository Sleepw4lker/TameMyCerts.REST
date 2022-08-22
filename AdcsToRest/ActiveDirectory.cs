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
    public class ActiveDirectory
    {
        /// <summary>
        ///     Retrieves a certification authority and the templates bound to it from Active Directory.
        /// </summary>
        /// <param name="certificateAuthority">The name of the target certificate authority.</param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        /// <exception cref="HttpResponseException">
        ///     Throws a HTTP 404 error if the specified certificate authority was not found in Active Directory.
        /// </exception>
        public static CertificateAuthority GetCertificateAuthority(string certificateAuthority,
            bool prettyPrintCertificate = false)
        {
            var searchResults = GetEnrollmentServiceCollection(certificateAuthority);

            if (searchResults.Count != 1)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA,
                        certificateAuthority))
                });
            }

            return new CertificateAuthority(searchResults[0], prettyPrintCertificate);
        }

        /// <summary>
        ///     Retrieves a list of all certificate authorities in the Active Directory forest, and the templates bound to each.
        /// </summary>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        public static CertificateAuthorityCollection GetCertificateAuthorityList(bool prettyPrintCertificate = false)
        {
            var searchResults = GetEnrollmentServiceCollection();

            return new CertificateAuthorityCollection((from SearchResult searchResult in searchResults
                select new CertificateAuthority(searchResult, prettyPrintCertificate)).ToList());
        }

        /// <summary>
        ///     Retrieves the configuration string for a certificate authority.
        /// </summary>
        /// <param name="certificateAuthority">The name of the target certificate authority.</param>
        /// <returns>The configuration string, built from the CA's DNS name and the CA common name.</returns>
        /// <exception cref="HttpResponseException">
        ///     Throws a HTTP 404 error if the specified certificate authority was not found in
        ///     Active Directory.
        /// </exception>
        public static string GetConfigString(string certificateAuthority)
        {
            var certificateAuthorityServerName = GetCertificateAuthorityServerName(certificateAuthority);

            if (null == certificateAuthorityServerName)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CA,
                        certificateAuthority))
                });
            }

            return $"{certificateAuthorityServerName}\\{certificateAuthority}";
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
    }
}