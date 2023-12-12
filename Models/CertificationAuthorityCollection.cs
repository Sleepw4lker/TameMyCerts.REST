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
using System.DirectoryServices;
using System.Linq;

namespace TameMyCerts.REST.Models
{
    /// <summary>
    ///     A collection of CertificationAuthority Objects.
    /// </summary>
    public class CertificationAuthorityCollection
    {
        /// <summary>
        ///     Builds a CertificationAuthorityCollection out of a given list.
        /// </summary>
        /// <param name="certificationAuthorities">The collection of certification authorities.</param>
        public CertificationAuthorityCollection(List<CertificationAuthority> certificationAuthorities)
        {
            CertificationAuthorities = certificationAuthorities;
        }

        /// <summary>
        ///     Builds a CertificationAuthorityCollection out of the information available in Active Directory.
        /// </summary>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        public CertificationAuthorityCollection(bool textualEncoding = false)
        {
            var searchResults = ActiveDirectory.GetEnrollmentServiceCollection();

            CertificationAuthorities = (from SearchResult searchResult in searchResults
                select new CertificationAuthority(searchResult, textualEncoding)).ToList();
        }

        /// <summary>
        ///     A collection of CertificationAuthority Objects.
        /// </summary>
        public List<CertificationAuthority> CertificationAuthorities { get; }
    }
}