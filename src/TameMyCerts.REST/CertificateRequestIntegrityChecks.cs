// Copyright (c) Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Runtime.InteropServices;
using CERTENROLLLib;
using TameMyCerts.REST.Enums;

namespace TameMyCerts.REST;

/// <summary>
///     A class that helps identifying the type of the certificate request and harmonizing it for further processing.
/// </summary>
public static class CertificateRequestIntegrityChecks
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
        switch (requestType)
        {
            case CertCli.CR_IN_PKCS10:
                return TryDecode(() => new CX509CertificateRequestPkcs10(), certificateRequest,
                    (request, input) => request.InitializeDecode(input, EncodingType.XCN_CRYPT_STRING_BASE64_ANY),
                    out rawCertificateRequest);

            case CertCli.CR_IN_PKCS7:
                return TryDecode(() => new CX509CertificateRequestPkcs7(), certificateRequest,
                    (request, input) => request.InitializeDecode(input, EncodingType.XCN_CRYPT_STRING_BASE64_ANY),
                    out rawCertificateRequest);

            case CertCli.CR_IN_CMC:
                return TryDecode(() => new CX509CertificateRequestCmc(), certificateRequest,
                    (request, input) => request.InitializeDecode(input, EncodingType.XCN_CRYPT_STRING_BASE64_ANY),
                    out rawCertificateRequest);

            default:
                rawCertificateRequest = string.Empty;
                return false;
        }
    }

    /// <summary>
    ///     Creates a certificate request COM object of the given type, decodes it via <paramref name="decode" />,
    ///     and always releases it afterwards, even if decoding throws. <c>IX509CertificateRequestPkcs10</c>,
    ///     <c>...Pkcs7</c> and <c>...Cmc</c> each declare their own InitializeDecode, so it's passed in rather
    ///     than called directly against the shared IX509CertificateRequest base.
    /// </summary>
    private static bool TryDecode<T>(Func<T> factory, string certificateRequest, Action<T, string> decode,
        out string rawCertificateRequest)
        where T : IX509CertificateRequest
    {
        var request = factory();

        try
        {
            decode(request, certificateRequest);
            rawCertificateRequest = request.RawData;
            return true;
        }
        catch
        {
            rawCertificateRequest = string.Empty;
            return false;
        }
        finally
        {
            Marshal.ReleaseComObject(request);
        }
    }

    /// <summary>
    ///     Identifies the type of the given certificate request.
    /// </summary>
    /// <param name="certificateRequest">
    ///     The input certificate request as BASE64 encoded DER.
    /// </param>
    /// <param name="rawCertificateRequest">The output certificate request as BASE64 encoded DER.</param>
    /// <returns>The request type to be used with ICertRequest::Submit.</returns>
    public static int DetectRequestType(string certificateRequest, out string rawCertificateRequest)
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

        return 0; // Unknown request type
    }
}
