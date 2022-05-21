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
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest.Controllers
{
    public class GetCACertificateController : ApiController
    {
        /// <summary>
        ///     Retrieves the certification authority certificate for a given certification authority.
        /// </summary>
        [Authorize]
        [Route("getcacertificate/{certificationAuthority}")]
        public IssuedCertificate Get(string certificationAuthority, [FromUri] bool includeCertificateChain = false)
        {
            var getCaCertificateRequest = new GetCACertificateRequest
            {
                CertificationAuthority = certificationAuthority,
                IncludeCertificateChain = includeCertificateChain
            };

            return GetCACertificate(getCaCertificateRequest);
        }

        /// <summary>
        ///     Retrieves the certification authority certificate for a given certification authority.
        /// </summary>
        [Authorize]
        [Route("getcacertificate")]
        public IssuedCertificate Post(GetCACertificateRequest getCaCertificateRequest)
        {
            return GetCACertificate(getCaCertificateRequest);
        }

        private static IssuedCertificate GetCACertificate(GetCACertificateRequest getCaCertificateRequest)
        {
            if (null == getCaCertificateRequest.CertificationAuthority)
            {
                throw new HttpResponseException(HttpStatusCode.BadRequest);
            }

            if (!EnrollmentHelper.GetConfigString(getCaCertificateRequest.CertificationAuthority, out var configString))
            {
                throw new HttpResponseException(HttpStatusCode.NotFound);
            }

            var certRequestInterface = new CCertRequest();
            IssuedCertificate result;

            try
            {
                var outputFlags = CertCli.CR_OUT_BASE64HEADER;
                if (getCaCertificateRequest.IncludeCertificateChain)
                {
                    outputFlags |= CertCli.CR_OUT_CHAIN;
                }

                result = new IssuedCertificate
                (
                    WinError.ERROR_SUCCESS,
                    certRequestInterface.GetRequestId(),
                    0, null,
                    certRequestInterface.GetCACertificate(0, configString, outputFlags)
                );
            }
            catch (Exception ex)
            {
                result = new IssuedCertificate(ex.HResult, ex.Message);
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
                GC.Collect();
            }

            return result;
        }
    }
}