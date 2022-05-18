// Copyright 2021 Uwe Gradenegger

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
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;
using CERTENROLLLib;

namespace AdcsToRest.Controllers
{
    public class RequestCertificateController : ApiController
    {
        /// <summary>
        ///     Submits a certificate signing request (CSR) to a given certification authority
        /// </summary>
        [Authorize]
        //[Route("submit")]
        public IssuedCertificate Post(RequestCertificateRequest req)
        {
            if (null == req.CertificateRequest || null == req.CertificationAuthority ||
                null == req.CertificateTemplate)
            {
                return new IssuedCertificate
                {
                    StatusCode = WinError.ERROR_BAD_ARGUMENTS,
                    StatusMessage = new Win32Exception(WinError.ERROR_BAD_ARGUMENTS).Message,
                    Description = "Invalid Arguments specified."
                };
            }

            if (!EnrollmentHelper.GetConfigString(req.CertificationAuthority, out var configString))
            {
                return new IssuedCertificate
                {
                    StatusCode = WinError.ERROR_BAD_ARGUMENTS,
                    StatusMessage = new Win32Exception(WinError.ERROR_BAD_ARGUMENTS).Message,
                    Description = "The specified Certification Authority was not found."
                };
            }

            var certificateRequest = req.CertificateRequest;
            string rawCertificateRequest;
            var submissionFlags = CertCli.CR_IN_BASE64;

            switch (req.RequestType)
            {
                case CertCli.CR_IN_PKCS10:

                    // Short form would raise an E_NOINTERFACE exception on Windows 2012 R2 and earlier
                    var certRequestPkcs10 =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

                    try
                    {
                        certRequestPkcs10.InitializeDecode(
                            req.CertificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        rawCertificateRequest = certRequestPkcs10.RawData;
                        submissionFlags |= CertCli.CR_IN_PKCS10;
                    }
                    catch
                    {
                        return new IssuedCertificate
                        {
                            StatusCode = WinError.ERROR_INVALID_DATA,
                            Description = "Unable to interpret the given Certificate Request."
                        };
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
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        rawCertificateRequest = certRequestPkcs7.RawData;
                        submissionFlags |= CertCli.CR_IN_PKCS7;
                    }
                    catch
                    {
                        return new IssuedCertificate
                        {
                            StatusCode = WinError.ERROR_INVALID_DATA,
                            Description = "Unable to interpret the given Certificate Request."
                        };
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
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );

                        rawCertificateRequest = certRequestCmc.RawData;
                        submissionFlags |= CertCli.CR_IN_CMC;
                    }
                    catch
                    {
                        return new IssuedCertificate
                        {
                            StatusCode = WinError.ERROR_INVALID_DATA,
                            Description = "Unable to interpret the given Certificate Request."
                        };
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestCmc);
                    }

                    break;

                default:

                    return new IssuedCertificate
                    {
                        StatusCode = WinError.ERROR_INVALID_DATA,
                        Description = "Unable to interpret the given Certificate Request."
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
                return new IssuedCertificate
                {
                    StatusCode = ex.HResult,
                    StatusMessage = ex.Message,
                    Description = "Impersonation failed."
                };
            }

            var certRequestInterface = new CCertRequest();
            var arguments = new ArrayList
            {
                $"CertificateTemplate:{req.CertificateTemplate}"
            };
            IssuedCertificate result;

            try
            {
                foreach (var requestAttribute in req.RequestAttributes)
                {
                    arguments.Add(requestAttribute);
                }

                var submissionResult = certRequestInterface.Submit(
                    submissionFlags,
                    rawCertificateRequest,
                    string.Join(Environment.NewLine, arguments.ToArray()),
                    configString
                );

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
                        $"Unable to submit the request to {configString} as user {WindowsIdentity.GetCurrent().Name} because {ex.Message}."
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