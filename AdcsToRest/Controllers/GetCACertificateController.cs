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
        [Route("api/getcacertificate/{certificationAuthority}")]
        public IssuedCertificate Get(string certificationAuthority, [FromUri] bool includeCertificateChain)
        {
            var req = new GetCACertificateRequest
            {
                CertificationAuthority = certificationAuthority,
                IncludeCertificateChain = includeCertificateChain
            };

            return GetCACertificate(req);
        }

        /// <summary>
        ///     Retrieves the certification authority certificate for a given certification authority.
        /// </summary>
        [Authorize]
        [Route("api/getcacertificate")]
        public IssuedCertificate Post(GetCACertificateRequest req)
        {
            return GetCACertificate(req);
        }

        private IssuedCertificate GetCACertificate(GetCACertificateRequest req)
        {
            if (null == req.CertificationAuthority)
            {
                return new IssuedCertificate
                {
                    StatusCode = WinError.ERROR_BAD_ARGUMENTS,
                    StatusMessage = new Win32Exception(WinError.ERROR_BAD_ARGUMENTS).Message,
                    Description = "Invalid Arguments specified. CertificationAuthority is a mandatory parameter."
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

            var certRequestInterface = new CCertRequest();
            IssuedCertificate result;

            try
            {
                var outputFlags = CertCli.CR_OUT_BASE64HEADER;
                if (req.IncludeCertificateChain)
                {
                    outputFlags |= CertCli.CR_OUT_CHAIN;
                }

                result = new IssuedCertificate
                {
                    StatusCode = WinError.ERROR_SUCCESS,
                    StatusMessage = new Win32Exception(WinError.ERROR_SUCCESS).Message,
                    RequestId = certRequestInterface.GetRequestId(),
                    Certificate = certRequestInterface.GetCACertificate(0, configString, outputFlags),
                    Description = "The certification authority certificate was successfully retrieved."
                };
            }
            catch (Exception ex)
            {
                result = new IssuedCertificate
                {
                    StatusCode = ex.HResult,
                    StatusMessage = new Win32Exception(ex.HResult).Message,
                    RequestId = certRequestInterface.GetRequestId()
                };
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