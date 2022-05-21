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

using System.DirectoryServices;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest
{
    internal class EnrollmentHelper
    {
        public static IssuedCertificate ProcessEnrollmentResult(ref CCertRequest certRequestInterface,
            int disposition, bool includeCertificateChain = false)
        {
            var result = new IssuedCertificate
            (
                certRequestInterface.GetLastStatus(),
                certRequestInterface.GetRequestId(),
                disposition,
                certRequestInterface.GetDispositionMessage()
            );

            if (disposition == CertCli.CR_DISP_ISSUED)
            {
                var outputFlags = CertCli.CR_OUT_BASE64HEADER;

                if (includeCertificateChain)
                {
                    outputFlags |= CertCli.CR_OUT_CHAIN;
                }

                result.Certificate = certRequestInterface.GetCertificate(outputFlags);
            }

            return result;
        }

        public static bool GetConfigString(string certificationAuthority, out string configString)
        {
            configString = string.Empty;

            var searchResult = GetCertificationAuthority(certificationAuthority);

            if (null == searchResult)
            {
                return false;
            }

            configString = $"{searchResult.Properties["dNSHostName"][0]}\\{certificationAuthority}";

            return true;
        }

        private static string GetForestRootDomain()
        {
            try
            {
                var directoryEntry = new DirectoryEntry("LDAP://RootDSE");
                return directoryEntry.Properties["rootDomainNamingContext"][0].ToString();
            }
            catch
            {
                return null;
            }
        }

        private static SearchResult GetCertificationAuthority(string cn)
        {
            if (null == cn)
            {
                return null;
            }

            var domainPath = GetForestRootDomain();

            if (null == domainPath)
            {
                return null;
            }

            var enrollmentContainer =
                $"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{domainPath}";

            var directoryEntry = new DirectoryEntry(enrollmentContainer);

            var directorySearcher = new DirectorySearcher(directoryEntry)
            {
                Filter = $"(&(cn={cn})(objectCategory=pKIEnrollmentService))"
            };

            var searchResults = directorySearcher.FindAll();

            // If found, there can only be one
            return searchResults.Count == 1 ? searchResults[0] : null;
        }
    }
}