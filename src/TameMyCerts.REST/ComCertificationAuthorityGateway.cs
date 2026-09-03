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
using System.Security.Principal;
using CERTCLILib;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     Talks to a certification authority over DCOM, via the ICertRequest COM interface.
/// </summary>
public sealed class ComCertificationAuthorityGateway : ICertificationAuthorityGateway
{
    /// <inheritdoc />
    public SubmissionResponse RetrievePending(string configString, int requestId, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        return WindowsIdentity.RunImpersonated(identity.AccessToken, () =>
        {
            var certRequestInterface = new CCertRequest();

            try
            {
                return certRequestInterface.RetrievePending(configString, requestId, textualEncoding);
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        });
    }

    /// <inheritdoc />
    public SubmissionResponse Submit(string configString, string rawCertificateRequest,
        List<string> requestAttributes, int submissionFlags, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        return WindowsIdentity.RunImpersonated(identity.AccessToken, () =>
        {
            var certRequestInterface = new CCertRequest();

            try
            {
                return certRequestInterface.Submit(configString, rawCertificateRequest, requestAttributes,
                    submissionFlags, textualEncoding);
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        });
    }

    /// <inheritdoc />
    public SubmissionResponse GetCaCertificate(string configString, bool textualEncoding = false,
        bool caExchangeCertificate = false)
    {
        var certRequestInterface = new CCertRequest();

        try
        {
            return certRequestInterface.GetCaCertificate(configString, textualEncoding, caExchangeCertificate);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }

    /// <inheritdoc />
    public CertificateRevocationListDistributionPointCollection GetCrlDpCollection(string configString,
        bool textualEncoding = false)
    {
        var certRequestInterface = new CCertRequest();

        try
        {
            return certRequestInterface.GetCrlDpCollection(configString, textualEncoding);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }

    /// <inheritdoc />
    public AuthorityInformationAccessCollection GetAiaCollection(string configString, bool textualEncoding = false)
    {
        var certRequestInterface = new CCertRequest();

        try
        {
            return certRequestInterface.GetAiaCollection(configString, textualEncoding);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }
}
