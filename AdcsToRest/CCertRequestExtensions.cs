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
using System.Net;
using System.Net.Http;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest
{
    /// <summary>
    ///     A class that extends the functionality if ICertRequest for the needs of our API.
    /// </summary>
    public static class CCertRequestExtensions
    {
        /// <summary>
        ///     Retrieves a certificate from a certificate authority.
        /// </summary>
        /// <param name="certRequestInterface"></param>
        /// <param name="configString">The configuration string of the certificate authority.</param>
        /// <param name="requestId"></param>
        /// <param name="includeCertificateChain">
        ///     Specifies if the certificate shall be returned as a PKCS#7 container that
        ///     includes the entire certificate chain.
        /// </param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        /// <exception cref="HttpResponseException">Throws a HTTP 500 error if not successful.</exception>
        public static SubmissionResponse RetrievePending(this CCertRequest certRequestInterface, string configString,
            int requestId, bool includeCertificateChain = false, bool prettyPrintCertificate = false)
        {
            try
            {
                var submissionResult =
                    certRequestInterface.RetrievePending(requestId, configString);

                return certRequestInterface.ProcessEnrollmentResult(submissionResult, includeCertificateChain,
                    prettyPrintCertificate);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED, ex.Message))
                });
            }
        }

        /// <summary>
        ///     Submits a certificate request to a certificate authority.
        /// </summary>
        /// <param name="certRequestInterface"></param>
        /// <param name="configString">The configuration string of the certificate authority.</param>
        /// <param name="rawCertificateRequest">The certificate request as BASE64 without headers.</param>
        /// <param name="requestAttributes">
        ///     An optional list of request attributes that shall be passed to the certificate
        ///     authority.
        /// </param>
        /// <param name="submissionFlags">Submission flags.</param>
        /// <param name="includeCertificateChain">
        ///     Specifies if the certificate shall be returned as a PKCS#7 container that
        ///     includes the entire certificate chain.
        /// </param>
        /// <param name="prettyPrintCertificate">Causes returned certificates to contain headers and line breaks.</param>
        /// <exception cref="HttpResponseException">Throws a HTTP 500 error if not successful.</exception>
        public static SubmissionResponse Submit(this CCertRequest certRequestInterface, string configString,
            string rawCertificateRequest, List<string> requestAttributes, int submissionFlags,
            bool includeCertificateChain, bool prettyPrintCertificate = false)
        {
            try
            {
                var submissionResult = certRequestInterface.Submit(
                    submissionFlags,
                    rawCertificateRequest,
                    string.Join(Environment.NewLine, requestAttributes.ToArray()),
                    configString
                );

                return certRequestInterface.ProcessEnrollmentResult(submissionResult,
                    includeCertificateChain, prettyPrintCertificate);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED, ex.Message))
                });
            }
        }

        private static SubmissionResponse ProcessEnrollmentResult(this CCertRequest certRequestInterface,
            int disposition, bool includeCertificateChain = false, bool prettyPrintCertificate = false)
        {
            var result = new SubmissionResponse
            (
                certRequestInterface.GetLastStatus(),
                certRequestInterface.GetRequestId(),
                disposition
            );

            if (disposition != CertCli.CR_DISP_ISSUED)
            {
                return result;
            }

            var outputFlags = 0;

            if (!prettyPrintCertificate)
            {
                outputFlags |= CertCli.CR_OUT_BASE64;
                outputFlags |= CertCli.CR_OUT_NOCRLF;
            }
            else
            {
                outputFlags |= CertCli.CR_OUT_BASE64HEADER;
            }

            if (includeCertificateChain)
            {
                outputFlags |= CertCli.CR_OUT_CHAIN;
            }

            result.Certificate = certRequestInterface.GetCertificate(outputFlags);

            return result;
        }
    }
}