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
///     Talks to a certification authority over DCOM: the ICertRequest COM interface (embedded interop,
///     CERTCLILib) for submission/retrieval/CA metadata, owned directly by this class; and an injected
///     <see cref="ICertAdminClient" /> for revocation and CA security. Owns impersonation for both.
/// </summary>
public sealed class ComCertificationAuthorityGateway : ICertificationAuthorityGateway
{
    private readonly ICertAdminClient _certAdminClient;

    /// <summary>
    ///     Builds the gateway.
    /// </summary>
    /// <param name="certAdminClient">The client to use for CA administration (revocation, CA security).</param>
    public ComCertificationAuthorityGateway(ICertAdminClient certAdminClient)
    {
        _certAdminClient = certAdminClient;
    }

    /// <inheritdoc />
    public SubmissionResponse RetrievePending(string configString, int requestId, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        return UseCertRequest(identity,
            certRequestInterface => certRequestInterface.RetrievePending(configString, requestId, textualEncoding));
    }

    /// <inheritdoc />
    public SubmissionResponse Submit(string configString, string rawCertificateRequest,
        List<string> requestAttributes, int submissionFlags, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        return UseCertRequest(identity, certRequestInterface => certRequestInterface.Submit(configString,
            rawCertificateRequest, requestAttributes, submissionFlags, textualEncoding));
    }

    /// <inheritdoc />
    public SubmissionResponse GetCaCertificate(string configString, bool textualEncoding = false,
        bool caExchangeCertificate = false)
    {
        return UseCertRequest(certRequestInterface =>
            certRequestInterface.GetCaCertificate(configString, textualEncoding, caExchangeCertificate));
    }

    /// <inheritdoc />
    public CertificateRevocationListDistributionPointCollection GetCrlDpCollection(string configString,
        bool textualEncoding = false)
    {
        return UseCertRequest(certRequestInterface =>
            certRequestInterface.GetCrlDpCollection(configString, textualEncoding));
    }

    /// <inheritdoc />
    public AuthorityInformationAccessCollection GetAiaCollection(string configString, bool textualEncoding = false)
    {
        return UseCertRequest(certRequestInterface => certRequestInterface.GetAiaCollection(configString,
            textualEncoding));
    }

    /// <inheritdoc />
    public void RevokeCertificate(string configString, string serialNumber, RevocationReason reason, DateTime date,
        WindowsIdentity identity)
    {
        UseCertAdmin(identity, () => _certAdminClient.RevokeCertificate(configString, serialNumber, reason, date));
    }

    /// <inheritdoc />
    public bool AllowsForCertificateManagement(string configString, WindowsIdentity identity)
    {
        var rawSecurityDescriptor =
            UseCertAdmin(identity, () => _certAdminClient.GetCaSecurityDescriptor(configString));

        var permission = new CertificateManagementPermission(rawSecurityDescriptor);

        return permission.AllowsForCertificateManagement(identity);
    }

    /// <summary>
    ///     Creates a CCertRequest COM object, runs <paramref name="action" /> against it, and always releases it
    ///     afterwards, even if <paramref name="action" /> throws.
    /// </summary>
    private static T UseCertRequest<T>(Func<CCertRequest, T> action)
    {
        var certRequestInterface = new CCertRequest();

        try
        {
            return action(certRequestInterface);
        }
        finally
        {
            Marshal.ReleaseComObject(certRequestInterface);
        }
    }

    /// <summary>
    ///     Same as <see cref="UseCertRequest{T}(Func{CCertRequest,T})" />, but impersonates
    ///     <paramref name="identity" /> for the duration of the call, so the certification authority applies that
    ///     identity's own enrollment permissions. The COM object is created, used, and released while still
    ///     impersonated, so the DCOM release call itself is made under the same identity that acquired it.
    /// </summary>
    private static T UseCertRequest<T>(WindowsIdentity identity, Func<CCertRequest, T> action)
    {
        return WindowsIdentity.RunImpersonated(identity.AccessToken, () => UseCertRequest(action));
    }

    /// <summary>
    ///     Impersonates <paramref name="identity" /> for the duration of <paramref name="action" />, so calls
    ///     the action makes through <see cref="_certAdminClient" /> run under - and the certification authority
    ///     applies - that identity's own CA management permissions.
    /// </summary>
    private static void UseCertAdmin(WindowsIdentity identity, Action action)
    {
        WindowsIdentity.RunImpersonated(identity.AccessToken, action);
    }

    /// <summary>
    ///     Same as <see cref="UseCertAdmin(WindowsIdentity,Action)" />, but for calls that return a value.
    /// </summary>
    private static T UseCertAdmin<T>(WindowsIdentity identity, Func<T> action)
    {
        return WindowsIdentity.RunImpersonated(identity.AccessToken, action);
    }
}
