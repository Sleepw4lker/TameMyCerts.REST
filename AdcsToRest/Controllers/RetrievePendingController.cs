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
using System.Net.Http;
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

        private IssuedCertificate RetrievePending(RetrievePendingRequest retrievePendingRequest)
        {
            if (0 == retrievePendingRequest.RequestId)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_PARAMETER, "requestId")),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_PARAMETER
                });
            }

            if (null == retrievePendingRequest.CertificationAuthority)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_PARAMETER,
                        "certificationAuthority")),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_PARAMETER
                });
            }

            if (!EnrollmentHelper.GetConfigString(retrievePendingRequest.CertificationAuthority, out var configString))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CERTIFICATIONAUTHORITY,
                        retrievePendingRequest.CertificationAuthority)),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_CERTIFICATIONAUTHORITY
                });
            }

            #region The following part runs under the security context of the authenticated user

            var impersonationContext = ((WindowsIdentity) User.Identity).Impersonate();

            var certRequestInterface = new CCertRequest();

            try
            {
                var submissionResult =
                    certRequestInterface.RetrievePending(retrievePendingRequest.RequestId, configString);

                return EnrollmentHelper.ProcessEnrollmentResult(ref certRequestInterface, submissionResult,
                    retrievePendingRequest.IncludeCertificateChain);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED,
                        retrievePendingRequest.CertificationAuthority, ex.Message)),
                    ReasonPhrase = LocalizedStrings.ERR_SUBMISSION_FAILED
                });
            }
            finally
            {
                // Important: ALWAYS undo the Impersonation when done
                impersonationContext.Undo();

                Marshal.ReleaseComObject(certRequestInterface);
                GC.Collect();
            }

            #endregion
        }
    }
}