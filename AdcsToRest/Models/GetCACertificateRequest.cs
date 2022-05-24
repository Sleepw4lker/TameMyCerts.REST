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

namespace AdcsToRest.Models
{
    public class GetCACertificateRequest
    {
        /// <summary>
        ///     The common name of the target certification authority.
        /// </summary>
        public string CertificationAuthority { get; set; }

        /// <summary>
        ///     When set to true, the Certificate response property will be a PKCS#7 container including the certificate chain
        ///     instead of a plain certificate.
        /// </summary>
        public bool IncludeCertificateChain { get; set; }
    }
}