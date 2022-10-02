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
using System.Linq;
using Microsoft.Win32;

namespace AdcsToRest.Models
{
    /// <summary>
    ///     A collection of CertificateTemplate Objects.
    /// </summary>
    public class CertificateTemplateCollection
    {
        private readonly string[] _defaultCertificateTemplates =
        {
            "CAExchange",
            "CrossCA",
            "DirectoryEmailReplication",
            "DomainControllerAuthentication",
            "KerberosAuthentication",
            "KeyRecoveryAgent",
            "OCSPResponseSigning",
            "RASAndIASServer",
            "Workstation"
        };

        /// <summary>
        ///     Builds a CertificateTemplateCollection.
        /// </summary>
        public CertificateTemplateCollection()
        {
            var machineBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var templateBaseKey =
                machineBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache");

            if (templateBaseKey == null)
            {
                return;
            }

            CertificateTemplates = templateBaseKey.GetSubKeyNames()
                .Where(templateName => !_defaultCertificateTemplates.Contains(templateName))
                .Select(templateName => new CertificateTemplate(templateName))
                .Where(certificateTemplate => certificateTemplate.SchemaVersion > 1).ToList();
        }

        /// <summary>
        ///     Builds a CertificateTemplateCollection.
        /// </summary>
        public CertificateTemplateCollection(List<CertificateTemplate> certificateTemplates)
        {
            CertificateTemplates = certificateTemplates;
        }

        /// <summary>
        ///     A collection of CertificateTemplate Objects.
        /// </summary>
        public List<CertificateTemplate> CertificateTemplates { get; set; }
    }
}