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

namespace AdcsToRest.Models
{
    /// <summary>
    ///     Information about a certificate template.
    /// </summary>
    public class CertificateTemplate
    {
        /// <summary>
        ///     TODO
        /// </summary>
        public enum KeyAlgorithmType
        {
            RSA = 1,
            ECDSA_P256 = 2,
            ECDSA_P384 = 3,
            ECDSA_P521 = 4,
            ECDH_P256 = 5,
            ECDH_P384 = 6,
            ECDH_P521 = 7
        }

        /// <summary>
        ///     TODO
        /// </summary>
        /// <param name="searchResult"></param>
        public CertificateTemplate(SearchResult searchResult)
        {
            var extendedKeyUsages = new List<string>();

            foreach (var extendedKeyUsage in searchResult.Properties["msPKI-Certificate-Application-Policy"])
            {
                extendedKeyUsages.Add(extendedKeyUsage.ToString());
            }

            extendedKeyUsages.Sort();

            Name = (string) searchResult.Properties["cn"][0];
            MinimumKeyLength = (int) searchResult.Properties["msPKI-minimal-Key-Size"][0];
            MajorVersion = (int) searchResult.Properties["revision"][0];
            MinorVersion = (int) searchResult.Properties["msPKI-Template-Minor-Revision"][0];
            Oid = (string) searchResult.Properties["msPKI-Cert-Template-OID"][0];
            ExtendedKeyUsages = extendedKeyUsages;
            KeyAlgorithm = GetKeyAlgorithm(searchResult.Properties["msPKI-RA-Application-Policies"]);
        }

        /// <summary>
        ///     The common name of the certificate template.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///     The minimum accepted key length of the certificate template.
        /// </summary>
        public int MinimumKeyLength { get; set; }

        /// <summary>
        ///     The major version of the certificate template.
        /// </summary>
        public int MajorVersion { get; set; }

        /// <summary>
        ///     The minor version of the certificate template.
        /// </summary>
        public int MinorVersion { get; set; }

        /// <summary>
        ///     The object identifier of the certificate template.
        /// </summary>
        public string Oid { get; set; }

        // TODO: Enumerate OIDs and translate to friendly name as well
        /// <summary>
        ///     A list of extended key usages of the certificate template.
        /// </summary>
        public List<string> ExtendedKeyUsages { get; set; }

        /// <summary>
        ///     Specifies the key algorithm the certificate will be signed with.
        /// </summary>
        public KeyAlgorithmType KeyAlgorithm { get; set; }

        private KeyAlgorithmType GetKeyAlgorithm(ResultPropertyValueCollection resultPropertyValueCollection)
        {
            if (resultPropertyValueCollection.Count == 0)
            {
                return KeyAlgorithmType.RSA;
            }

            foreach (var algorithmName in Enum.GetNames(typeof(KeyAlgorithmType)))
            {
                if (((string) resultPropertyValueCollection[0]).Contains(algorithmName))
                {
                    return (KeyAlgorithmType) Enum.Parse(typeof(KeyAlgorithmType), algorithmName);
                }
            }

            return KeyAlgorithmType.RSA;
        }
    }
}