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
    ///     A data structure containing authority information access for a certificate authority.
    /// </summary>
    public class AuthorityInformationAccess
    {
        /// <summary>
        ///     A collection of authority information access urls that are available for the certification authority certificate.
        /// </summary>
        public List<string> Urls { get; set; }

        /// <summary>
        ///     A collection of online certificate status protocol urls that are available for the certification authority
        ///     certificate.
        /// </summary>
        public List<string> OcspUrls { get; set; }

        /// <summary>
        ///     The X.509 V3 certification authority certificate. Always returned as BASE64-encoded DER with header (also known
        ///     as PEM).
        /// </summary>
        public string Certificate { get; set; }
    }
}