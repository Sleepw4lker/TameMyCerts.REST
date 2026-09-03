using System.Security.Principal;
using TameMyCerts.REST.Enums;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     Builds minimal, valid <see cref="CertificationAuthority" /> and <see cref="CertificateTemplate" />
///     instances for tests, via their data-only constructors (no Active Directory or registry involved).
/// </summary>
internal static class TestModels
{
    public static SecurityIdentifier CurrentUserSid => WindowsIdentity.GetCurrent().User!;

    public static CertificationAuthority CertificationAuthority(string name = "Contoso CA", bool allowed = true,
        List<string>? certificateTemplates = null)
    {
        return new CertificationAuthority(
            name,
            "ca.contoso.com",
            [0x30, 0x03, 0x02, 0x01, 0x00],
            certificateTemplates ?? [],
            allowed ? TestSecurityDescriptors.Allowing(CurrentUserSid) : TestSecurityDescriptors.Denying(CurrentUserSid));
    }

    public static CertificateTemplate CertificateTemplate(string name = "WebServer", bool allowed = true,
        int schemaVersion = 2)
    {
        return new CertificateTemplate(
            name: name,
            displayName: name,
            minimumKeyLength: 2048,
            majorVersion: 100,
            minorVersion: 0,
            schemaVersion: schemaVersion,
            objectIdentifier: "1.2.3.4.5",
            keyStorageProviders: ["Microsoft Software Key Storage Provider"],
            validityPeriod: TimeSpan.FromDays(365),
            renewalOverlap: TimeSpan.FromDays(42),
            enrolleeSuppliesSubject: false,
            keyUsageExtension: new KeyUsageExtension([0], false),
            extendedKeyUsageExtension: new ExtendedKeyUsageExtension([], false),
            keyAlgorithm: KeyAlgorithmType.RSA,
            rawSecurityDescriptor: allowed
                ? TestSecurityDescriptors.Allowing(CurrentUserSid)
                : TestSecurityDescriptors.Denying(CurrentUserSid));
    }
}
