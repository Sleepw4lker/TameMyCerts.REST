using System.Security.AccessControl;
using System.Security.Principal;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     Builds raw (binary) security descriptors carrying "Enroll" object ACEs and/or "Issue and Manage
///     Certificates" access-mask ACEs, for feeding <see cref="TameMyCerts.REST.Models.EnrollmentPermission" />,
///     <see cref="TameMyCerts.REST.Models.CertificateManagementPermission" />, and the model constructors that
///     build them, without needing a real Active Directory object or registry key.
/// </summary>
internal static class TestSecurityDescriptors
{
    private static readonly Guid EnrollPermission = new("0E10C968-78FB-11D2-90D4-00C04F79DC55");
    private const int CertificateManagementAccessMask = 0x2; // CA_ACCESS_OFFICER

    public static byte[] Empty()
    {
        return Build([]);
    }

    public static byte[] Allowing(SecurityIdentifier sid)
    {
        return Build([EnrollAce(AceQualifier.AccessAllowed, sid)]);
    }

    public static byte[] Denying(SecurityIdentifier sid)
    {
        return Build([EnrollAce(AceQualifier.AccessDenied, sid)]);
    }

    public static byte[] AllowingButDenying(SecurityIdentifier allowed, SecurityIdentifier denied)
    {
        return Build([EnrollAce(AceQualifier.AccessAllowed, allowed), EnrollAce(AceQualifier.AccessDenied, denied)]);
    }

    public static byte[] AllowingCertificateManagement(SecurityIdentifier sid)
    {
        return Build([ManagementAce(AceQualifier.AccessAllowed, sid)]);
    }

    public static byte[] DenyingCertificateManagement(SecurityIdentifier sid)
    {
        return Build([ManagementAce(AceQualifier.AccessDenied, sid)]);
    }

    public static byte[] AllowingButDenyingCertificateManagement(SecurityIdentifier allowed,
        SecurityIdentifier denied)
    {
        return Build([ManagementAce(AceQualifier.AccessAllowed, allowed), ManagementAce(AceQualifier.AccessDenied, denied)]);
    }

    /// <summary>
    ///     Builds a descriptor carrying both an "Enroll" object ACE and an "Issue and Manage Certificates"
    ///     access-mask ACE for the same principal, each independently allowed or denied - mirroring how a real
    ///     pKIEnrollmentService security descriptor carries both kinds of ACE side by side.
    /// </summary>
    public static byte[] Combined(SecurityIdentifier sid, bool allowEnrollment, bool allowCertificateManagement)
    {
        return Build([
            EnrollAce(allowEnrollment ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, sid),
            ManagementAce(allowCertificateManagement ? AceQualifier.AccessAllowed : AceQualifier.AccessDenied, sid)
        ]);
    }

    private static ObjectAce EnrollAce(AceQualifier qualifier, SecurityIdentifier sid)
    {
        return new ObjectAce(
            AceFlags.None,
            qualifier,
            0,
            sid,
            ObjectAceFlags.ObjectAceTypePresent,
            EnrollPermission,
            Guid.Empty,
            false,
            null);
    }

    private static CommonAce ManagementAce(AceQualifier qualifier, SecurityIdentifier sid)
    {
        return new CommonAce(AceFlags.None, qualifier, CertificateManagementAccessMask, sid, false, null);
    }

    private static byte[] Build(IReadOnlyList<GenericAce> aces)
    {
        var acl = new RawAcl(RawAcl.AclRevisionDS, aces.Count);

        for (var index = 0; index < aces.Count; index++)
        {
            acl.InsertAce(index, aces[index]);
        }

        var securityDescriptor = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null,
            acl);

        var result = new byte[securityDescriptor.BinaryLength];
        securityDescriptor.GetBinaryForm(result, 0);
        return result;
    }
}
