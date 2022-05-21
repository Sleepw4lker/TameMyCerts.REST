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

using System.ComponentModel;
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
                null,
                certRequestInterface.GetRequestId(),
                disposition,
                certRequestInterface.GetDispositionMessage()
            );

            switch (disposition)
            {
                case CertCli.CR_DISP_DENIED:

                    result.Description = "The certificate request was denied by the certification authority.";
                    break;

                case CertCli.CR_DISP_ERROR:

                    result.Description = "The certification authority was unable to process the certificate request.";
                    break;

                case CertCli.CR_DISP_INCOMPLETE:

                    result.Description = "The certificate request was incomplete.";
                    break;

                case CertCli.CR_DISP_UNDER_SUBMISSION:

                    result.Description = "The certificate request is under Submission.";
                    break;

                case CertCli.CR_DISP_ISSUED_OUT_OF_BAND:

                    result.Description = "The certificate was issued out of Band.";
                    break;

                case CertCli.CR_DISP_ISSUED:

                    // https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-getcertificate
                    var outputFlags = CertCli.CR_OUT_BASE64HEADER;

                    // Include the certificate chain. Causes the certificate to get returned as a PKCS#7 message.
                    if (includeCertificateChain)
                    {
                        outputFlags |= CertCli.CR_OUT_CHAIN;
                    }

                    result.Description = "The certificate was issued.";
                    result.Certificate = certRequestInterface.GetCertificate(outputFlags);
                    break;

                default:

                    // This should never occur, but just to be sure
                    result.Description = "Unknown result processing the certificate request.";
                    break;
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