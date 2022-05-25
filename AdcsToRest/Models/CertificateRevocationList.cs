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
    public class CertificateRevocationList
    {
        /// <summary>
        ///     A collection of uniform resource locators the certificate revocation list is distributed by the certificate authority.
        /// </summary>
        public List<string> CrlDistributionPoints { get; set; }

        /// <summary>
        ///     The X.509 V2 certificate revocation list. Always returned as BASE64-encoded DER with header (also known
        ///     as PEM).
        /// </summary>
        public string Crl { get; set; }
    }
}