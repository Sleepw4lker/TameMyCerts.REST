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
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace AdcsToRest.Models
{
    /// <summary>
    ///     A data structure holding information about a certification authority.
    /// </summary>
    public class CertificationAuthority
    {
        /// <summary>
        ///     Builds the object from a SearchResult containing a pKIEnrollmentService LDAP object.
        /// </summary>
        /// <param name="searchResult"></param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64
        ///     stream.
        /// </param>
        public CertificationAuthority(SearchResult searchResult, bool textualEncoding = false)
        {
            Name = (string) searchResult.Properties["cn"][0];

            ConfigString = $"{searchResult.Properties["dNSHostName"][0]}\\{Name}";

            Certificate = GetCertificate((byte[]) searchResult.Properties["cACertificate"][0], textualEncoding);

            CertificateTemplates =
                (from object certificateTemplate in searchResult.Properties["certificateTemplates"]
                    select certificateTemplate.ToString()).ToList();

            CertificateTemplates.Sort();

            var rawSecurityDescriptor =
                new RawSecurityDescriptor((byte[]) searchResult.Properties["ntSecurityDescriptor"][0], 0);

            foreach (var genericAce in rawSecurityDescriptor.DiscretionaryAcl)
            {
                if (!(genericAce is ObjectAce objectAce))
                {
                    continue;
                }

                if (objectAce.ObjectAceType != new Guid("0E10C968-78FB-11D2-90D4-00C04F79DC55"))
                {
                    continue;
                }

                switch (objectAce.AceType)
                {
                    case AceType.AccessAllowedObject:
                        AllowedPrincipals.Add(objectAce.SecurityIdentifier.ToString());
                        break;
                    case AceType.AccessDeniedObject:
                        DisallowedPrincipals.Add(objectAce.SecurityIdentifier.ToString());
                        break;
                }
            }
        }

        /// <summary>
        ///     The common name of the certification authority.
        /// </summary>
        public string Name { get; set; }

        [JsonIgnore]
        public string ConfigString { get; set; }

        /// <summary>
        ///     A list of all certificate templates offered by the certification authority.
        /// </summary>
        public List<string> CertificateTemplates { get; set; }

        /// <summary>
        ///     The current certification authority certificate of the certification authority.
        /// </summary>
        public string Certificate { get; set; }

        private List<string> AllowedPrincipals { get; } = new List<string>();
        private List<string> DisallowedPrincipals { get; } = new List<string>();

        /// <summary>
        ///     Determines whether a given WindowsIdentity may enroll for this certification authority.
        /// </summary>
        /// <param name="identity">The Windows identity to check for permissions.</param>
        /// <param name="explicitlyPermitted">Return true only if the identity is explicitly mentioned in the acl.</param>
        /// <returns></returns>
        public bool AllowsForEnrollment(WindowsIdentity identity, bool explicitlyPermitted = false)
        {
            var isAllowed = false;
            var isDenied = false;

            var userSid = identity.User?.ToString();
            var ignoreCase = StringComparer.InvariantCultureIgnoreCase;

            if (!explicitlyPermitted)
            {
                for (var index = 0; index < identity.Groups?.Count; index++)
                {
                    var group = identity.Groups[index].ToString();

                    isAllowed = AllowedPrincipals.Contains(group, ignoreCase) || isAllowed;
                    isDenied = DisallowedPrincipals.Contains(group, ignoreCase) || isDenied;
                }
            }

            isAllowed = AllowedPrincipals.Contains(userSid, ignoreCase) || isAllowed;
            isDenied = DisallowedPrincipals.Contains(userSid, ignoreCase) || isDenied;

            return isAllowed && !isDenied;
        }

        private string GetCertificate(byte[] rawData, bool textualEncoding = false)
        {
            var certificate = Convert.ToBase64String(rawData);

            if (!textualEncoding)
            {
                return certificate;
            }

            certificate = Regex.Replace(certificate, ".{64}", "$&\r\n");
            certificate = $"-----BEGIN CERTIFICATE-----\r\n{certificate}\r\n-----END CERTIFICATE-----";

            return certificate;
        }
    }
}