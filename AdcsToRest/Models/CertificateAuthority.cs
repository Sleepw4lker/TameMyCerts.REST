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
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text.RegularExpressions;

namespace AdcsToRest.Models
{
    /// <summary>
    ///     A data structure holding information about a certificate authority.
    /// </summary>
    public class CertificateAuthority
    {
        /// <summary>
        ///     Builds the object from a SearchResult containing a pKIEnrollmentService LDAP object.
        /// </summary>
        /// <param name="searchResult"></param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        public CertificateAuthority(SearchResult searchResult, bool prettyPrintCertificate = false)
        {
            Name = (string) searchResult.Properties["cn"][0];

            Certificate = GetCertificate((byte[]) searchResult.Properties["cACertificate"][0], prettyPrintCertificate);

            CertificateTemplates =
                (from object certificateTemplate in searchResult.Properties["certificateTemplates"]
                    select certificateTemplate.ToString()).ToList();

            CertificateTemplates.Sort();
        }

        /// <summary>
        ///     The common name of the certificate authority.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///     A list of all certificate templates offered by the certificate authority.
        /// </summary>
        public List<string> CertificateTemplates { get; set; }

        /// <summary>
        ///     The current certificate authority certificate of the certificate authority.
        /// </summary>
        public string Certificate { get; set; }

        private string GetCertificate(byte[] rawData, bool prettyPrintCertificate = false)
        {
            var certificate = Convert.ToBase64String(rawData);

            if (!prettyPrintCertificate)
            {
                return certificate;
            }

            certificate = Regex.Replace(certificate, ".{64}", "$&\r\n");
            certificate = $"-----BEGIN CERTIFICATE-----\r\n{certificate}\r\n-----END CERTIFICATE-----";

            return certificate;
        }
    }
}