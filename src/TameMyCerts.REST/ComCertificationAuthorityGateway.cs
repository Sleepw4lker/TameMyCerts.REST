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
///     Talks to a certification authority over DCOM, via the ICertRequest COM interface for
///     submission/retrieval/CA metadata, and the ICertAdmin/ICertAdmin2 interfaces for revocation and CA
///     security. These have no embedded interop types (unlike ICertRequest's CERTCLILib) - they're accessed
///     late-bound, via ICertAdmin's well-known ProgID, so this doesn't require a new
///     &lt;COMReference&gt; and the tlbimp build step that comes with it.
/// </summary>
public sealed class ComCertificationAuthorityGateway : ICertificationAuthorityGateway
{
    private const string CertAdminProgId = "CertificateAuthority.Admin";

    // CCertAdmin's default automation interface (what plain late-bound `dynamic` resolves methods against) is
    // the original ICertAdmin - RevokeCertificate lives there, so it just works. GetConfigEntry only exists on
    // ICertAdmin2, a separate dual interface CCertAdmin also implements but does not expose as its default
    // IDispatch. Reaching it therefore needs an explicit COM QueryInterface, which this marker interface
    // triggers when a dynamic reference is cast to it; the empty body is enough; the IID is all that matters.
    [ComImport]
    [Guid("f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    private interface ICertAdmin2
    {
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
    public void RevokeCertificate(string configString, string serialNumber, RevocationReason reason,
        WindowsIdentity identity)
    {
        UseCertAdmin(identity, certAdminInterface =>
            certAdminInterface.RevokeCertificate(configString, serialNumber, (int)reason,
                DateTime.UtcNow.ToOADate()));
    }

    /// <inheritdoc />
    public bool AllowsForCertificateManagement(string configString, WindowsIdentity identity)
    {
        // The "Security" leaf entry under the CA's own configuration root holds the same raw security
        // descriptor `certutil -getreg CA\Security` prints - ICertAdmin2::GetConfigEntry is the DCOM equivalent
        // of that registry read, requiring no more permission than certutil itself does. Per [MS-CSRA]
        // GetConfigEntry (Opnum 44), an empty node path plus entry name "Security" is the documented case for
        // this value - certutil's "CA\" prefix is its own display grouping, not a literal node path.
        byte[] rawSecurityDescriptor = UseCertAdmin(identity, certAdminInterface =>
        {
            dynamic certAdmin2 = (ICertAdmin2)certAdminInterface;
            return (byte[])certAdmin2.GetConfigEntry(configString, string.Empty, "Security");
        });

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
    ///     Same COM-safety as <see cref="UseCertRequest{T}(WindowsIdentity,Func{CCertRequest,T})" />: creates a
    ///     CCertAdmin COM object under the impersonated identity, runs <paramref name="action" /> against it, and
    ///     always releases it afterwards - while still impersonated - even if <paramref name="action" /> throws.
    ///     Late-bound (dynamic) rather than an embedded interop type, since ICertAdmin is only needed for this one
    ///     call; see the class summary.
    /// </summary>
    private static void UseCertAdmin(WindowsIdentity identity, Action<dynamic> action)
    {
        UseCertAdmin<object?>(identity, certAdminInterface =>
        {
            action(certAdminInterface);
            return null;
        });
    }

    /// <summary>
    ///     Same as <see cref="UseCertAdmin(WindowsIdentity,Action{dynamic})" />, but for calls that return a
    ///     value.
    /// </summary>
    private static T UseCertAdmin<T>(WindowsIdentity identity, Func<dynamic, T> action)
    {
        return WindowsIdentity.RunImpersonated(identity.AccessToken, () =>
        {
            var certAdminType = Type.GetTypeFromProgID(CertAdminProgId) ?? throw new InvalidOperationException(
                $"The '{CertAdminProgId}' COM class is not registered on this machine. " +
                "The AD CS management tools (or the CA role itself) need to be installed.");

            dynamic certAdminInterface = Activator.CreateInstance(certAdminType)!;

            try
            {
                return action(certAdminInterface);
            }
            finally
            {
                Marshal.ReleaseComObject(certAdminInterface);
            }
        });
    }
}
