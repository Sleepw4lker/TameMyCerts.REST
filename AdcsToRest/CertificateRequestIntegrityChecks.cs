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
using System.Runtime.InteropServices;
using CERTENROLLLib;

namespace AdcsToRest
{
    public class CertificateRequestIntegrityChecks
    {
        /// <summary>
        ///     Verifies if the certificate request can be parsed as defined by the requestType.
        /// </summary>
        /// <param name="certificateRequest">The certificate request in BASE64 format, with or without headers.</param>
        /// <param name="requestType">The request type specifies how the certificate request is to be interpreted.</param>
        /// <param name="rawCertificateRequest">
        ///     Harmonized certificate request, returned as BASE64 without header, regardless of
        ///     the given input.
        /// </param>
        private static bool VerifyCertificateRequest(string certificateRequest, int requestType,
            out string rawCertificateRequest)
        {
            rawCertificateRequest = null;

            switch (requestType)
            {
                case CertCli.CR_IN_PKCS10:

                    var certRequestPkcs10 =
                        (IX509CertificateRequestPkcs10) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

                    try
                    {
                        certRequestPkcs10.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );
                        rawCertificateRequest = certRequestPkcs10.RawData;
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestPkcs10);
                    }

                    break;

                case CertCli.CR_IN_PKCS7:

                    var certRequestPkcs7 =
                        (IX509CertificateRequestPkcs7) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                    try
                    {
                        certRequestPkcs7.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );
                        rawCertificateRequest = certRequestPkcs7.RawData;
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestPkcs7);
                    }

                    break;

                case CertCli.CR_IN_CMC:

                    var certRequestCmc =
                        (IX509CertificateRequestCmc) Activator.CreateInstance(
                            Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                    try
                    {
                        certRequestCmc.InitializeDecode(
                            certificateRequest,
                            EncodingType.XCN_CRYPT_STRING_BASE64_ANY
                        );
                        rawCertificateRequest = certRequestCmc.RawData;
                    }
                    catch
                    {
                        return false;
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(certRequestCmc);
                    }

                    break;

                default:

                    return false;
            }

            return true;
        }

        /// <summary>
        ///     Identifies the type of a given certificate request.
        /// </summary>
        /// <param name="certificateRequest">The input certificate request as BASE64 encoded string (aka PEM).</param>
        /// <param name="rawCertificateRequest">The input certificate request as BASE64 encoded string (aka PEM) without headers.</param>
        /// <returns>The request type to be used with ICertRequest::Submit</returns>
        public static int AutoDetectRequestType(string certificateRequest, out string rawCertificateRequest)
        {
            int[] validRequestTypes =
            {
                CertCli.CR_IN_PKCS10,
                CertCli.CR_IN_PKCS7,
                CertCli.CR_IN_CMC
            };

            rawCertificateRequest = string.Empty;

            foreach (var requestType in validRequestTypes)
            {
                if (VerifyCertificateRequest(certificateRequest, requestType, out rawCertificateRequest))
                {
                    return requestType;
                }
            }

            return 0;
        }
    }
}