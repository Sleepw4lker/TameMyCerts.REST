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
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Newtonsoft.Json;

namespace TameMyCerts.REST.Models
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

        private CertificateTemplate(string templateName, RegistryKey regKey)
        {
            const string enrollPermission = "0E10C968-78FB-11D2-90D4-00C04F79DC55";

            Name = templateName;
            DisplayName = (string) regKey.GetValue("DisplayName");
            MinimumKeyLength = (int) regKey.GetValue("msPKI-Minimal-Key-Size");
            MajorVersion = (int) regKey.GetValue("Revision");
            MinorVersion = (int) regKey.GetValue("msPKI-Template-Minor-Revision");
            SchemaVersion = (int) regKey.GetValue("msPKI-Template-Schema-Version");
            ObjectIdentifier = ((string[]) regKey.GetValue("msPKI-Cert-Template-OID"))[0];
            KeyStorageProviders = ((string[]) regKey.GetValue("SupportedCSPs")).ToList();
            ValidityPeriod = PkiPeriodToTimeSpan((byte[]) regKey.GetValue("ValidityPeriod"));
            RenewalOverlap = PkiPeriodToTimeSpan((byte[]) regKey.GetValue("RenewalOverlap"));

            EnrolleeSuppliesSubject =
                (CertCa.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT &
                 Convert.ToInt32(regKey.GetValue("msPKI-Certificate-Name-Flag"))) ==
                CertCa.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT;

            var criticalExtensions = (string[]) regKey.GetValue("CriticalExtensions");

            KeyUsageExtension = new KeyUsageExtension((byte[]) regKey.GetValue("KeyUsage"),
                criticalExtensions.Contains(WinCrypt.szOID_KEY_USAGE));

            ExtendedKeyUsageExtension =
                new ExtendedKeyUsageExtension((string[]) regKey.GetValue("ExtKeyUsageSyntax"),
                    criticalExtensions.Contains(WinCrypt.szOID_ENHANCED_KEY_USAGE) ||
                    criticalExtensions.Contains(WinCrypt.szOID_APPLICATION_CERT_POLICIES));

            var applicationPoliciesValueData = (string[]) regKey.GetValue("msPKI-RA-Application-Policies");

            KeyAlgorithm = applicationPoliciesValueData.Length > 0
                ? GetKeyAlgorithm(applicationPoliciesValueData[0])
                : KeyAlgorithmType.RSA;

            var rawSecurityDescriptor = new RawSecurityDescriptor((byte[]) regKey.GetValue("Security"), 0);

            foreach (var genericAce in rawSecurityDescriptor.DiscretionaryAcl)
            {
                if (!(genericAce is ObjectAce objectAce))
                {
                    continue;
                }

                if (objectAce.ObjectAceType != new Guid(enrollPermission))
                {
                    continue;
                }

                switch (objectAce.AceType)
                {
                    case AceType.AccessAllowedObject:
                        AllowedPrincipals.Add(objectAce.SecurityIdentifier);
                        break;
                    case AceType.AccessDeniedObject:
                        DisallowedPrincipals.Add(objectAce.SecurityIdentifier);
                        break;
                }
            }
        }

        /// <summary>
        ///     The common name of the certificate template. Use this when submitting certificate requests.
        /// </summary>
        public string Name { get; }

        /// <summary>
        ///     The display name of the certificate template.
        /// </summary>
        public string DisplayName { get; }

        /// <summary>
        ///     The object identifier of the certificate template.
        /// </summary>
        public string ObjectIdentifier { get; }

        /// <summary>
        ///     Specifies if the enrollee may provide subject information with the certificate request.
        /// </summary>
        public bool EnrolleeSuppliesSubject { get; }

        /// <summary>
        ///     Specifies the key algorithm the certificate will be signed with.
        /// </summary>
        public KeyAlgorithmType KeyAlgorithm { get; }

        /// <summary>
        ///     The minimum accepted key length of the certificate template.
        /// </summary>
        public int MinimumKeyLength { get; }

        /// <summary>
        ///     The validity period of issued certificates for this certificate template.
        /// </summary>
        public TimeSpan ValidityPeriod { get; }

        /// <summary>
        ///     The desired renewal overlap period for this certificate template.
        /// </summary>
        public TimeSpan RenewalOverlap { get; }

        /// <summary>
        ///     Contains a list of the preferred key storage providers for this certificate template.
        /// </summary>
        public List<string> KeyStorageProviders { get; }

        /// <summary>
        ///     The major version of the certificate template.
        /// </summary>
        public int MajorVersion { get; }

        /// <summary>
        ///     The minor version of the certificate template.
        /// </summary>
        public int MinorVersion { get; }

        /// <summary>
        ///     The Active Directory schema version of the certificate template.
        /// </summary>
        [JsonIgnore]
        public int SchemaVersion { get; }

        /// <summary>
        ///     Information about the key usage extension of the certificate template.
        /// </summary>
        public KeyUsageExtension KeyUsageExtension { get; }

        /// <summary>
        ///     Information about the extended key usage extension of the certificate template.
        /// </summary>
        public ExtendedKeyUsageExtension ExtendedKeyUsageExtension { get; }

        private List<SecurityIdentifier> AllowedPrincipals { get; } = new List<SecurityIdentifier>();
        private List<SecurityIdentifier> DisallowedPrincipals { get; } = new List<SecurityIdentifier>();

        /// <summary>
        ///     Builds a new CertificateTemplate object.
        /// </summary>
        /// <param name="templateName">The name of the certificate template from which the object is built.</param>
        public static CertificateTemplate Create(string templateName)
        {
            var machineBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var templateBaseKey =
                machineBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache");

            if (templateBaseKey?.OpenSubKey(templateName) is RegistryKey templateSubKey)
            {
                return new CertificateTemplate(templateName, templateSubKey);
            }

            return null;
        }

        /// <summary>
        ///     Determines whether a given WindowsIdentity may enroll for this certificate template.
        /// </summary>
        /// <param name="identity">The Windows identity to check for permissions.</param>
        /// <param name="explicitlyPermitted">Return true only if the identity is explicitly mentioned in the acl.</param>
        /// <returns></returns>
        public bool AllowsForEnrollment(WindowsIdentity identity, bool explicitlyPermitted = false)
        {
            var isAllowed = false;
            var isDenied = false;

            if (!explicitlyPermitted)
            {
                for (var index = 0; index < identity.Groups?.Count; index++)
                {
                    var group = (SecurityIdentifier) identity.Groups[index];
                    isAllowed = AllowedPrincipals.Contains(group) || isAllowed;
                    isDenied = DisallowedPrincipals.Contains(group) || isDenied;
                }
            }

            isAllowed = AllowedPrincipals.Contains(identity.User) || isAllowed;
            isDenied = DisallowedPrincipals.Contains(identity.User) || isDenied;

            return isAllowed && !isDenied;
        }

        private static KeyAlgorithmType GetKeyAlgorithm(string keyAlgorithmString)
        {
            foreach (var algorithmName in Enum.GetNames(typeof(KeyAlgorithmType)))
            {
                if (keyAlgorithmString.Contains($"msPKI-Asymmetric-Algorithm`PZPWSTR`{algorithmName}`"))
                {
                    return (KeyAlgorithmType) Enum.Parse(typeof(KeyAlgorithmType), algorithmName);
                }
            }

            return KeyAlgorithmType.RSA;
        }

        private static TimeSpan PkiPeriodToTimeSpan(byte[] value)
        {
            var period = BitConverter.ToInt64(value, 0);
            period /= -10000000;
            return TimeSpan.FromSeconds(period);
        }
    }
}