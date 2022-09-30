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
using System.Linq;
using Microsoft.Win32;

namespace AdcsToRest.Models
{
    /// <summary>
    ///     Information about a certificate template.
    /// </summary>
    public class CertificateTemplate
    {
        /// <summary>
        ///     Supported public key algorithm types.
        /// </summary>
        public enum KeyAlgorithmType
        {
            /// <summary>
            ///     The RSA algorithm.
            /// </summary>
            RSA = 1,

            /// <summary>
            ///     The elliptic curve digital signature algorithm using the nistp256 curve.
            /// </summary>
            ECDSA_P256 = 2,

            /// <summary>
            ///     The elliptic curve digital signature algorithm using the nistp384 curve.
            /// </summary>
            ECDSA_P384 = 3,

            /// <summary>
            ///     The elliptic curve digital signature algorithm using the nistp521 curve.
            /// </summary>
            ECDSA_P521 = 4,

            /// <summary>
            ///     The elliptic curve diffie hellman algorithm using the nistp256 curve.
            /// </summary>
            ECDH_P256 = 5,

            /// <summary>
            ///     The elliptic curve diffie hellman algorithm using the nistp384 curve.
            /// </summary>
            ECDH_P384 = 6,

            /// <summary>
            ///     The elliptic curve diffie hellman algorithm using the nistp521 curve.
            /// </summary>
            ECDH_P521 = 7
        }

        /// <summary>
        ///     An object holding information about a certificate template.
        /// </summary>
        /// <param name="certificateTemplate">The name of the certificate template from which the object is built.</param>
        public CertificateTemplate(string certificateTemplate)
        {
            var machineBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var templateBaseKey =
                machineBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache");

            var templateSubKey = templateBaseKey?.OpenSubKey(certificateTemplate);

            if (templateSubKey == null)
            {
                throw new ArgumentException(string.Format(LocalizedStrings.DESC_MISSING_TEMPLATE, certificateTemplate));
            }

            Name = certificateTemplate;
            MinimumKeyLength = (int) templateSubKey.GetValue("msPKI-Minimal-Key-Size");
            MajorVersion = (int) templateSubKey.GetValue("Revision");
            MinorVersion = (int) templateSubKey.GetValue("msPKI-Template-Minor-Revision");
            Oid = ((string[])templateSubKey.GetValue("msPKI-Cert-Template-OID"))[0];

            ExtendedKeyUsages = (from string extendedKeyUsage in (string[]) templateSubKey.GetValue("ExtKeyUsageSyntax")
                    select new ExtendedKeyUsage(extendedKeyUsage))
                .OrderBy(extendedKeyUsage => extendedKeyUsage.FriendlyName).ToList();
            
            var applicationPoliciesValueData = (string[]) templateSubKey.GetValue("msPKI-RA-Application-Policies");

            KeyAlgorithm = applicationPoliciesValueData.Length > 0
                ? GetKeyAlgorithm(applicationPoliciesValueData[0])
                : KeyAlgorithmType.RSA;
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

        /// <summary>
        ///     A list of extended key usages of the certificate template.
        /// </summary>
        public List<ExtendedKeyUsage> ExtendedKeyUsages { get; set; }

        /// <summary>
        ///     Specifies the key algorithm the certificate will be signed with.
        /// </summary>
        public KeyAlgorithmType KeyAlgorithm { get; set; }

        private KeyAlgorithmType GetKeyAlgorithm(string keyAlgorithmString)
        {
            foreach (var algorithmName in Enum.GetNames(typeof(KeyAlgorithmType)))
            {
                if (keyAlgorithmString.Contains(algorithmName))
                {
                    return (KeyAlgorithmType) Enum.Parse(typeof(KeyAlgorithmType), algorithmName);
                }
            }

            return KeyAlgorithmType.RSA;
        }
    }
}