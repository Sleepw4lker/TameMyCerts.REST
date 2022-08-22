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

namespace AdcsToRest.Models
{
    /// <summary>
    ///     A collection of CertificateAuthority Objects.
    /// </summary>
    public class CertificateAuthorityCollection
    {
        /// <summary>
        ///     Builds a CertificateAuthorityCollection.
        /// </summary>
        /// <param name="certificateAuthorities">The collection of certificate authorities.</param>
        public CertificateAuthorityCollection(List<CertificateAuthority> certificateAuthorities)
        {
            CertificateAuthorities = certificateAuthorities;
        }

        /// <summary>
        ///     A collection of CertificateAuthority Objects.
        /// </summary>
        public List<CertificateAuthority> CertificateAuthorities { get; set; }
    }
}