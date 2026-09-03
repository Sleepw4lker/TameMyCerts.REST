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
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     Talks to the CertificateAuthority.Admin COM class, late-bound via its well-known ProgID rather than an
///     embedded interop type, so this doesn't require a new &lt;COMReference&gt; and the tlbimp build step
///     that comes with it. Creates, uses, and releases the COM object for every single call - COM objects are
///     not reused across calls.
/// </summary>
public sealed class ComCertAdminClient : ICertAdminClient
{
    private const string CertAdminProgId = "CertificateAuthority.Admin";

    // CCertAdmin's default automation interface (what plain late-bound `dynamic` resolves methods against) is
    // the original ICertAdmin - RevokeCertificate lives there, so it just works. GetConfigEntry only exists on
    // ICertAdmin2, a separate dual interface CCertAdmin also implements but does not expose as its default
    // IDispatch. Reaching it therefore needs an explicit COM QueryInterface, which this marker interface
    // triggers when a dynamic reference is cast to it; the empty body is enough, the IID is all that matters.
    [ComImport]
    [Guid("f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    private interface ICertAdmin2
    {
    }

    /// <inheritdoc />
    public void RevokeCertificate(string configString, string serialNumber, RevocationReason reason, DateTime date)
    {
        UseCertAdmin(certAdminInterface =>
            certAdminInterface.RevokeCertificate(configString, serialNumber, (int)reason, date.ToOADate()));
    }

    /// <inheritdoc />
    public byte[] GetCaSecurityDescriptor(string configString)
    {
        // The "Security" leaf entry under the CA's own configuration root holds the same raw security
        // descriptor `certutil -getreg CA\Security` prints - ICertAdmin2::GetConfigEntry is the DCOM equivalent
        // of that registry read, requiring no more permission than certutil itself does. Per [MS-CSRA]
        // GetConfigEntry (Opnum 44), an empty node path plus entry name "Security" is the documented case for
        // this value - certutil's "CA\" prefix is its own display grouping, not a literal node path.
        return UseCertAdmin(certAdminInterface =>
        {
            dynamic certAdmin2 = (ICertAdmin2)certAdminInterface;
            return (byte[])certAdmin2.GetConfigEntry(configString, string.Empty, "Security");
        });
    }

    /// <summary>
    ///     Creates a CertificateAuthority.Admin COM object, runs <paramref name="action" /> against it, and
    ///     always releases it afterwards, even if <paramref name="action" /> throws.
    /// </summary>
    private static void UseCertAdmin(Action<dynamic> action)
    {
        UseCertAdmin<object?>(certAdminInterface =>
        {
            action(certAdminInterface);
            return null;
        });
    }

    /// <summary>
    ///     Same as <see cref="UseCertAdmin(Action{dynamic})" />, but for calls that return a value.
    /// </summary>
    private static T UseCertAdmin<T>(Func<dynamic, T> action)
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
    }
}
