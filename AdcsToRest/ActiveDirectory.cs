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
using System.DirectoryServices;
using System.Linq;
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
                throw new ArgumentException(LocalizedStrings.DESC_MISSING_CA);
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
                PropertiesToLoad =
                    {"cn", "certificateTemplates", "dNSHostName", "cACertificate", "ntSecurityDescriptor"},
                SecurityMasks = SecurityMasks.Dacl
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