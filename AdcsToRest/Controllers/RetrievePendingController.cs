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
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest.Controllers
{
    public class RetrievePendingController : ApiController
    {
        /// <summary>
        ///     Retrieves an issued certificate from a given certification authority.
        /// </summary>
        [Authorize]
        [Route("retrievepending/{certificationAuthority}/{requestId}")]
        public IssuedCertificate Get(string certificationAuthority, int requestId,
            [FromUri] bool includeCertificateChain = false)
        {
            var retrievePendingRequest = new RetrievePendingRequest
            {
                CertificationAuthority = certificationAuthority,
                RequestId = requestId,
                IncludeCertificateChain = includeCertificateChain
            };

            return RetrievePending(retrievePendingRequest);
        }

        /// <summary>
        ///     Retrieves an issued certificate from a given certification authority.
        /// </summary>
        [Authorize]
        [Route("retrievepending")]
        public IssuedCertificate Post(RetrievePendingRequest retrievePendingRequest)
        {
            return RetrievePending(retrievePendingRequest);
        }

        private IssuedCertificate RetrievePending(RetrievePendingRequest req)
        {
            if (0 == req.RequestId || null == req.CertificationAuthority)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }

            if (!EnrollmentHelper.GetConfigString(req.CertificationAuthority, out var configString))
            {
                throw new HttpResponseException(HttpStatusCode.NotFound);
            }

            #region The following part runs under the security context of the authenticated user

            var impersonationContext = ((WindowsIdentity) User.Identity).Impersonate();

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
                (
                    ex.HResult,
                    $"Unable to submit the request to {configString} as user {WindowsIdentity.GetCurrent().Name} because {ex.Message}."
                );
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