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
using Newtonsoft.Json;

namespace AdcsToRest.Models
{
    public class CertificateRequest
    {
        /// <summary>
        ///     The X.509 certificate signing request as BASE64 encoded DER (aka PEM) string. PKCS#10, PKCS#7/CMS and CMC are
        ///     supported and are detected automatically.
        /// </summary>
        [JsonRequired]
        public string Request { get; set; }

        /// <summary>
        ///     Optional request attributes as a collection of strings. A request attribute is declared as a name-value pair
        ///     separated by a colon. For example, to specify a certificate template name, you would add
        ///     "CertificateTemplate:TemplateNameHere".
        /// </summary>
        public List<string> RequestAttributes { get; set; } = new List<string>();
    }
}