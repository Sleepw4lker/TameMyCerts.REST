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
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest.Controllers
{
    public class RetrieveCertificateController : ApiController
    {
        /// <summary>
        ///     Retrieves an issued certificate from a given certification authority.
        /// </summary>
        [Authorize]
        [Route("api/retrievecertificate/{certificationAuthority}/{requestId}")]
        public IssuedCertificate Get(string certificationAuthority, int requestId, [FromUri] bool includeCertificateChain)
        {
            var req = new RetrieveCertificateRequest
            {
                CertificationAuthority = certificationAuthority,
                RequestId = requestId,
                IncludeCertificateChain = includeCertificateChain
            };

            return RetrieveCertificate(req);
        }

        /// <summary>
        ///     Retrieves an issued certificate from a given certification authority.
        /// </summary>
        [Authorize]
        [Route("api/retrievecertificate")]
        public IssuedCertificate Post(RetrieveCertificateRequest req)
        {
            return RetrieveCertificate(req);
        }

        private IssuedCertificate RetrieveCertificate (RetrieveCertificateRequest req) 
        {
            if (0 == req.RequestId || null == req.CertificationAuthority)
            {
                return new IssuedCertificate
                {
                    StatusCode = WinError.ERROR_BAD_ARGUMENTS,
                    StatusMessage = new Win32Exception(WinError.ERROR_BAD_ARGUMENTS).Message,
                    Description =
                        "Invalid Arguments specified. CertificationAuthority and RequestId are mandatory parameters."
                };
            }

            if (!EnrollmentHelper.GetConfigString(req.CertificationAuthority, out var configString))
            {
                return new IssuedCertificate
                {
                    StatusCode = WinError.ERROR_BAD_ARGUMENTS,
                    StatusMessage = new Win32Exception(WinError.ERROR_BAD_ARGUMENTS).Message,
                    Description = $"The certification authority \"{req.CertificationAuthority}\" was not found."
                };
            }

            #region The following part runs under the security context of the authenticated user

            // https://docs.microsoft.com/en-us/troubleshoot/aspnet/implement-impersonation

            WindowsImpersonationContext impersonationContext;

            try
            {
                impersonationContext = ((WindowsIdentity) User.Identity).Impersonate();
            }
            catch (Exception ex)
            {
                // TODO: This will probably not return any HResult
                return new IssuedCertificate
                {
                    StatusCode = ex.HResult,
                    StatusMessage = ex.Message,
                    Description = "Impersonation failed."
                };
            }

            var certRequestInterface = new CCertRequest();
            IssuedCertificate result;

            try
            {
                var submissionResult = certRequestInterface.RetrievePending(req.RequestId, configString);

                result = EnrollmentHelper.ProcessEnrollmentResult(ref certRequestInterface, submissionResult,
                    req.IncludeCertificateChain);
            }
            catch (Exception ex)
            {
                result = new IssuedCertificate
                {
                    StatusCode = ex.HResult,
                    StatusMessage = new Win32Exception(ex.HResult).Message,
                    RequestId = certRequestInterface.GetRequestId(),
                    Description =
                        $"Unable to submit the request to {configString} as user {WindowsIdentity.GetCurrent().Name} because {ex.Message}. Impersonation Level: {((WindowsIdentity) User.Identity).ImpersonationLevel}."
                };
            }
            finally
            {
                // Important: ALWAYS undo the Impersonation when done
                impersonationContext.Undo();

                Marshal.ReleaseComObject(certRequestInterface);
                GC.Collect();
            }

            return result;

            #endregion
        }
    }
}