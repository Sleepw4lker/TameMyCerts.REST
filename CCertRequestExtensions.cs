﻿// Copyright (c) Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using CERTCLILib;
using TameMyCerts.NetCore.Common.Enums;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     A class that extends the functionality if ICertRequest for the needs of our API.
/// </summary>
public static class CCertRequestExtensions
{
    /// <summary>
    ///     Retrieves a certificate from a certification authority.
    /// </summary>
    /// <param name="certRequestInterface"></param>
    /// <param name="configString">The configuration string of the certification authority.</param>
    /// <param name="requestId"></param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    public static SubmissionResponse RetrievePending(this CCertRequest certRequestInterface, string configString,
        int requestId, bool textualEncoding = false)
    {
        var submissionResult =
            certRequestInterface.RetrievePending(requestId, configString);

        return certRequestInterface.ProcessEnrollmentResult(submissionResult, textualEncoding);
    }

    /// <summary>
    ///     Submits a certificate request to a certification authority.
    /// </summary>
    /// <param name="certRequestInterface"></param>
    /// <param name="configString">The configuration string of the certification authority.</param>
    /// <param name="rawCertificateRequest">The certificate request as BASE64 without headers.</param>
    /// <param name="requestAttributes">
    ///     An optional list of request attributes that shall be passed to the certificate
    ///     authority.
    /// </param>
    /// <param name="submissionFlags">Submission flags.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    public static SubmissionResponse Submit(this CCertRequest certRequestInterface, string configString,
        string rawCertificateRequest, List<string> requestAttributes, int submissionFlags,
        bool textualEncoding = false)
    {
        var submissionResult = certRequestInterface.Submit(
            submissionFlags,
            rawCertificateRequest,
            string.Join(Environment.NewLine, requestAttributes.ToArray()),
            configString
        );

        return certRequestInterface.ProcessEnrollmentResult(submissionResult, textualEncoding);
    }

    private static SubmissionResponse ProcessEnrollmentResult(this CCertRequest certRequestInterface,
        int disposition, bool textualEncoding = false)
    {
        var outputFlags = 0;

        if (!textualEncoding)
        {
            outputFlags |= CertCli.CR_OUT_BASE64;
            outputFlags |= CertCli.CR_OUT_NOCRLF;
        }
        else
        {
            outputFlags |= CertCli.CR_OUT_BASE64HEADER;
        }

        if (disposition != CertCli.CR_DISP_ISSUED && disposition != CertCli.CR_DISP_REVOKED)
        {
            return new SubmissionResponse
            (
                certRequestInterface.GetLastStatus(),
                certRequestInterface.GetRequestId(),
                disposition,
                certRequestInterface.GetFullResponseProperty(CertCli.FR_PROP_FULLRESPONSE, 0, CertSrv.PROPTYPE_BINARY,
                    outputFlags)
            );
        }

        return new SubmissionResponse
        (
            certRequestInterface.GetLastStatus(),
            certRequestInterface.GetRequestId(),
            disposition,
            certRequestInterface.GetFullResponseProperty(CertCli.FR_PROP_FULLRESPONSE, 0, CertSrv.PROPTYPE_BINARY,
                outputFlags),
            certRequestInterface.GetCertificate(outputFlags),
            certRequestInterface.GetCertificate(outputFlags | CertCli.CR_OUT_CHAIN)
        );
    }

    /// <summary>
    ///     Retrieves certificate revocation list distribution point information from a certification authority.
    /// </summary>
    /// <param name="certRequestInterface"></param>
    /// <param name="configString">The configuration string of the certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    public static CertificateRevocationListDistributionPointCollection GetCrlDpCollection(
        this CCertRequest certRequestInterface,
        string configString, bool textualEncoding = false)
    {
        var outputFlags = 0;

        if (!textualEncoding)
        {
            outputFlags |= CertView.CV_OUT_BASE64;
            outputFlags |= CertView.CV_OUT_NOCRLF;
        }
        else
        {
            outputFlags |= CertView.CV_OUT_BASE64X509CRLHEADER;
        }

        int caCertCount = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CASIGCERTCOUNT, 0,
            CertSrv.PROPTYPE_LONG, 0);

        var crlList = new List<CertificateRevocationListDistributionPoint>();

        for (var index = caCertCount - 1; index >= 0; index--)
        {
            int crlState = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CRLSTATE, index,
                CertSrv.PROPTYPE_LONG, 0);

            if (crlState != CertAdm.CA_DISP_VALID)
            {
                continue;
            }

            string crlDistributionPoints = certRequestInterface.GetCAProperty(configString,
                CertCli.CR_PROP_CERTCDPURLS, index,
                CertSrv.PROPTYPE_STRING, 0);

            crlList.Add(new CertificateRevocationListDistributionPoint(
                crlDistributionPoints.Split(new[] { "\n" }, StringSplitOptions.RemoveEmptyEntries).ToList(),
                certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_BASECRL, index,
                    CertSrv.PROPTYPE_BINARY, outputFlags)));
        }

        return new CertificateRevocationListDistributionPointCollection(crlList);
    }

    /// <summary>
    ///     Retrieves authority information access information from a certification authority.
    /// </summary>
    /// <param name="certRequestInterface"></param>
    /// <param name="configString">The configuration string of the certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    public static AuthorityInformationAccessCollection GetAiaCollection(this CCertRequest certRequestInterface,
        string configString, bool textualEncoding = false)
    {
        int caCertCount = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CASIGCERTCOUNT, 0,
            CertSrv.PROPTYPE_LONG, 0);

        var aiaList = new List<AuthorityInformationAccess>();

        var outputFlags = 0;

        if (!textualEncoding)
        {
            outputFlags |= CertView.CV_OUT_BASE64;
            outputFlags |= CertView.CV_OUT_NOCRLF;
        }
        else
        {
            outputFlags |= CertView.CV_OUT_BASE64HEADER;
        }

        for (var index = caCertCount - 1; index >= 0; index--)
        {
            string aiaUrls = certRequestInterface.GetCAProperty(configString,
                CertCli.CR_PROP_CERTAIAURLS, index,
                CertSrv.PROPTYPE_STRING, 0);

            string aiaOcspUrls = certRequestInterface.GetCAProperty(configString,
                CertCli.CR_PROP_CERTAIAOCSPURLS, index,
                CertSrv.PROPTYPE_STRING, 0);

            aiaList.Add(new AuthorityInformationAccess(
                aiaUrls.Split(new[] { "\n" }, StringSplitOptions.RemoveEmptyEntries).ToList(),
                aiaOcspUrls.Split(new[] { "\n" }, StringSplitOptions.RemoveEmptyEntries).ToList(),
                certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CASIGCERT, index,
                    CertSrv.PROPTYPE_BINARY, outputFlags)));
        }

        return new AuthorityInformationAccessCollection(aiaList);
    }

    /// <summary>
    ///     Retrieves a CA or CA exchange certificate from a certification authority.
    /// </summary>
    /// <param name="certRequestInterface"></param>
    /// <param name="configString">The configuration string of the certification authority.</param>
    /// <param name="caExchangeCertificate">Returns the CA exchange certificate instead of the CA certificate.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    public static SubmissionResponse GetCaCertificate(this CCertRequest certRequestInterface, string configString,
        bool textualEncoding = false, bool caExchangeCertificate = false)
    {
        var outputFlags = 0;

        if (!textualEncoding)
        {
            outputFlags |= CertCli.CR_OUT_BASE64;
            outputFlags |= CertCli.CR_OUT_NOCRLF;
        }
        else
        {
            outputFlags |= CertCli.CR_OUT_BASE64HEADER;
        }

        return new SubmissionResponse
        (
            WinError.ERROR_SUCCESS,
            0,
            (int)SubmissionResponse.DispositionCode.Issued,
            string.Empty,
            certRequestInterface.GetCACertificate(caExchangeCertificate ? 1 : 0, configString, outputFlags),
            certRequestInterface.GetCACertificate(caExchangeCertificate ? 1 : 0, configString,
                outputFlags | CertCli.CR_OUT_CHAIN)
        );
    }
}