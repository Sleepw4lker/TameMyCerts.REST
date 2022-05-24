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
using CERTENROLLLib;

namespace AdcsToRest.Controllers
{
    public class SubmitController : ApiController
    {
        /// <summary>
        ///     Submits a certificate signing request (CSR) to a given certification authority.
        /// </summary>
        [Authorize]
        [Route("submit")]
        public IssuedCertificate Post(SubmitRequest submitRequest)
        {
            return Submit(submitRequest);
        }

        private IssuedCertificate Submit(SubmitRequest submitRequest)
        {
            if (null == submitRequest.CertificateRequest)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content =
                        new StringContent(string.Format(LocalizedStrings.DESC_MISSING_PARAMETER, "CertificateRequest")),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_PARAMETER
                });
            }

            if (null == submitRequest.CertificationAuthority)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_PARAMETER,
                        "certificationAuthority")),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_PARAMETER
                });
            }

            if (!EnrollmentHelper.GetConfigString(submitRequest.CertificationAuthority, out var configString))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_MISSING_CERTIFICATIONAUTHORITY,
                        submitRequest.CertificationAuthority)),
                    ReasonPhrase = LocalizedStrings.ERR_MISSING_CERTIFICATIONAUTHORITY
                });
            }

            string rawCertificateRequest;
            var submissionFlags = CertCli.CR_IN_BASE64;

            switch (submitRequest.RequestType)
            {
                case CertCli.CR_IN_PKCS10:

                    // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
                    var certRequestPkcs10 =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

                    try
                    {
                        certRequestPkcs10.InitializeDecode(
                            submitRequest.CertificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        rawCertificateRequest = certRequestPkcs10.RawData;
                        submissionFlags |= CertCli.CR_IN_PKCS10;
                    }
                    catch
                    {
                        throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                        {
                            Content = new StringContent(string.Format(LocalizedStrings.DESC_INVALID_CSR,
                                submitRequest.RequestType)),
                            ReasonPhrase = LocalizedStrings.ERR_INVALID_CSR
                        });
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestPkcs10);
                    }

                    break;

                case CertCli.CR_IN_PKCS7:

                    // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
                    var certRequestPkcs7 =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                    try
                    {
                        certRequestPkcs7.InitializeDecode(
                            submitRequest.CertificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        rawCertificateRequest = certRequestPkcs7.RawData;
                        submissionFlags |= CertCli.CR_IN_PKCS7;
                    }
                    catch
                    {
                        throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                        {
                            Content = new StringContent(string.Format(LocalizedStrings.DESC_INVALID_CSR,
                                submitRequest.RequestType)),
                            ReasonPhrase = LocalizedStrings.ERR_INVALID_CSR
                        });
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestPkcs7);
                    }

                    break;

                case CertCli.CR_IN_CMC:

                    // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
                    var certRequestCmc =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                    try
                    {
                        certRequestCmc.InitializeDecode(
                            submitRequest.CertificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        rawCertificateRequest = certRequestCmc.RawData;
                        submissionFlags |= CertCli.CR_IN_CMC;
                    }
                    catch
                    {
                        throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                        {
                            Content = new StringContent(string.Format(LocalizedStrings.DESC_INVALID_CSR,
                                submitRequest.RequestType)),
                            ReasonPhrase = LocalizedStrings.ERR_INVALID_CSR
                        });
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestCmc);
                    }

                    break;

                default:

                    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        Content = new StringContent(string.Format(LocalizedStrings.DESC_INVALID_CSR,
                            submitRequest.RequestType)),
                        ReasonPhrase = LocalizedStrings.ERR_INVALID_CSR
                    });
            }

            #region The following part runs under the security context of the authenticated user

            var impersonationContext = ((WindowsIdentity) User.Identity).Impersonate();


            var certRequestInterface = new CCertRequest();

            try
            {
                var submissionResult = certRequestInterface.Submit(
                    submissionFlags,
                    rawCertificateRequest,
                    string.Join(Environment.NewLine, submitRequest.RequestAttributes.ToArray()),
                    configString
                );

                return EnrollmentHelper.ProcessEnrollmentResult(ref certRequestInterface, submissionResult,
                    submitRequest.IncludeCertificateChain);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED,
                        submitRequest.CertificationAuthority, ex.Message)),
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