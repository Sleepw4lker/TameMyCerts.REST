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
    public class SubmitRequest
    {
        /// <summary>
        ///     The common name of the target certification authority.
        /// </summary>
        public string CertificationAuthority { get; set; }

        /// <summary>
        ///     When set to true, the response will be a PKCS#7 container including the certificate chain instead of a plain
        ///     certificate.
        /// </summary>
        public bool IncludeCertificateChain { get; set; } = false;

        /// <summary>
        ///     The certificate request as BASE64 encoded DER (aka PEM) string. PKCS#10, PKCS#7/CMS and CMC are supported. See
        ///     RequestType parameter.
        /// </summary>
        public string CertificateRequest { get; set; }

        /// <summary>
        ///     The type of the submitted certificate request constant as defined in CertCli.h. Possible Values: 0x100 (PKCS#10),
        ///     0x300 (PKCS#7), 0x400 (CMC). Defaults to PKCS#10.
        /// </summary>
        public int RequestType { get; set; } = CertCli.CR_IN_PKCS10;

        /// <summary>
        ///     Optional request attributes as a collection of strings. A request attribute is declared as a name-value pair
        ///     separated by a colon. For example, to specify a certificate template name, you would add
        ///     "CertificateTemplate:TemplateNameHere".
        /// </summary>
        public List<string> RequestAttributes { get; set; } = new List<string>();
    }
}